use anyhow::{Context, Result};
use clap::Parser;
use futures::{Stream, StreamExt, pin_mut};
use log::{error, info, warn};
use photon_indexer::common::{setup_logging, LoggingFormat};
use photon_indexer::snapshot::{create_snapshot_from_byte_stream, DirectoryAdapter};
use reqwest::{Response, StatusCode};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;
use bytes::Bytes;
use futures::stream;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::pin::Pin;

/// Photon Loader: a utility to load snapshots from a snapshot server
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Snapshot url
    #[arg(short, long)]
    snapshot_server_url: String,

    /// Snapshot directory
    #[arg(long)]
    snapshot_dir: String,

    /// Logging format
    #[arg(short, long, default_value_t = LoggingFormat::Standard)]
    logging_format: LoggingFormat,
    
    /// Max retry attempts
    #[arg(long, default_value_t = 10)]
    max_retries: u32,
    
    /// Retry delay in seconds
    #[arg(long, default_value_t = 15)]
    retry_delay: u64,
    
    /// Resume download if temp file exists
    #[arg(long, default_value_t = true)]
    resume: bool,
    
    /// Chunk size for downloads in KB (larger values may improve speed but use more memory)
    #[arg(long, default_value_t = 1024)]
    chunk_size_kb: usize,
}

// Function to find the temp file with the largest size in the snapshot directory
fn find_largest_temp_file(snapshot_dir: &str) -> Option<(PathBuf, u64)> {
    let temp_dir = std::env::temp_dir().join(snapshot_dir);
    if !temp_dir.exists() {
        return None;
    }
    
    let entries = match std::fs::read_dir(temp_dir) {
        Ok(entries) => entries,
        Err(_) => return None,
    };
    
    let mut largest_file: Option<(PathBuf, u64)> = None;
    
    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.is_file() && path.file_name().unwrap_or_default().to_string_lossy().starts_with("temp-snapshot-") {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    let size = metadata.len();
                    match &largest_file {
                        None => largest_file = Some((path, size)),
                        Some((_, largest_size)) if size > *largest_size => largest_file = Some((path, size)),
                        _ => {}
                    }
                }
            }
        }
    }
    
    largest_file
}

// Function to make a HTTP request with specified range
async fn make_range_request(
    client: &reqwest::Client, 
    url: &str, 
    range_start: u64,
    max_retries: u32,
    retry_delay: u64
) -> Result<Response> {
    let mut retry_count = 0;
    let mut last_error_msg;
    
    loop {
        info!("Requesting range starting at byte position {} ({:.2} MB)", 
              range_start, range_start as f64 / (1024.0 * 1024.0));
              
        let req_builder = client.get(url)
            .header("Range", format!("bytes={}-", range_start))
            .header("Connection", "keep-alive")
            .header("Keep-Alive", "timeout=600") // 10 minute keep-alive
            .timeout(Duration::from_secs(600)); // 10 minute timeout per request
        
        match req_builder.send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() || status == StatusCode::PARTIAL_CONTENT || status == StatusCode::RANGE_NOT_SATISFIABLE {
                    info!("Server responded with status code: {}", status);
                    if let Some(range) = response.headers().get("Content-Range") {
                        info!("Content-Range: {}", range.to_str().unwrap_or("invalid"));
                    }
                    if let Some(length) = response.content_length() {
                        info!("Content-Length: {} bytes ({:.2} MB)", 
                              length, length as f64 / (1024.0 * 1024.0));
                    }
                    return Ok(response);
                } else {
                    let error_text = response.text().await.unwrap_or_default();
                    last_error_msg = format!("HTTP error: {} - {}", status, error_text);
                    error!("{}", last_error_msg);
                }
            },
            Err(e) => {
                last_error_msg = format!("Request error: {}", e);
                error!("{}", last_error_msg);
                
                // Provide more specific error information
                if e.is_timeout() {
                    error!("Request timed out. Network might be unstable.");
                } else if e.is_connect() {
                    error!("Connection error. Network might be down or server unreachable.");
                } else if e.is_body() {
                    error!("Body error. Data transfer was interrupted.");
                }
            }
        }
        
        retry_count += 1;
        if retry_count >= max_retries {
            return Err(anyhow::anyhow!("Max retries reached. Last error: {}", last_error_msg));
        }
        
        let backoff = Duration::from_secs(retry_delay * retry_count as u64);
        warn!("Retrying in {} seconds (attempt {}/{})", backoff.as_secs(), retry_count, max_retries);
        sleep(backoff).await;
    }
}

// Function to implement resumable downloads
async fn download_with_resume(
    client: &reqwest::Client,
    url: &str,
    temp_file_path: &PathBuf,
    max_retries: u32,
    retry_delay: u64,
    chunk_size_kb: usize
) -> Result<u64> {
    let mut file = if temp_file_path.exists() {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp_file_path)
            .context("Failed to open existing temp file")?;
        
        // Get the current size to resume from
        let file_size = file.metadata()?.len();
        info!("Resuming download from byte position {}", file_size);
        file
    } else {
        std::fs::File::create(temp_file_path).context("Failed to create temp file")?
    };
    
    // Get the file size for resuming
    let file_size = file.metadata()?.len();
    file.seek(SeekFrom::End(0))?;
    
    // Download and append to file with retry logic
    let mut total_bytes = file_size;
    let mut current_position = file_size;
    
    loop {
        let response = make_range_request(client, url, current_position, max_retries, retry_delay).await?;
        
        // If we get a 416 Range Not Satisfiable, it means we're done
        if response.status() == StatusCode::RANGE_NOT_SATISFIABLE {
            info!("Download complete: server indicates no more data");
            break;
        }
        
        let content_length = response.content_length();
        if let Some(cl) = content_length {
            info!("Downloading {} bytes", cl);
        }
        
        // Use custom stream handling with timeout for each chunk
        let stream = response.bytes_stream();
        let mut had_data = false;
        
        // Use a fixed buffer size based on chunk_size_kb
        let chunk_buffer_size = chunk_size_kb * 1024;
        info!("Using chunk size of {} KB for download", chunk_size_kb);
        
        pin_mut!(stream);
        
        while let Some(chunk_result) = tokio::time::timeout(
            Duration::from_secs(60), // 60 second timeout per chunk
            stream.next()
        ).await.unwrap_or_else(|_| {
            error!("Timeout waiting for data chunk");
            None
        }) {
            match chunk_result {
                Ok(chunk) => {
                    had_data = true;
                    let chunk_size = chunk.len() as u64;
                    
                    // Check if the chunk looks valid
                    if chunk_size > chunk_buffer_size as u64 * 2 {
                        warn!("Unusually large chunk received ({} bytes). This might indicate a download issue.", chunk_size);
                    }
                    
                    match file.write_all(&chunk) {
                        Ok(_) => {
                            if let Err(e) = file.flush() {
                                error!("Failed to flush file: {}", e);
                                break;
                            }
                            
                            current_position += chunk_size;
                            total_bytes += chunk_size;
                            
                            if total_bytes % (10 * 1024 * 1024) == 0 { // Log every 10MB
                                info!("Downloaded {} MB so far ({:.2}MB/s)", 
                                      total_bytes / (1024 * 1024),
                                      chunk_size as f64 / 1_048_576.0); // Show approximate speed
                            }
                        },
                        Err(e) => {
                            error!("Failed to write chunk to file: {}", e);
                            break;
                        }
                    }
                },
                Err(e) => {
                    error!("Error downloading chunk: {} (connection may have been interrupted)", e);
                    warn!("Will attempt to resume download from byte position {}", current_position);
                    break;
                }
            }
        }
        
        // If we didn't get any data in this iteration, we might be done or have an error
        if !had_data {
            if current_position > file_size {
                info!("Download finished or connection closed. Downloaded {} MB total", total_bytes / (1024 * 1024));
                break;
            } else {
                warn!("No data received but download not complete. Will retry from byte position {}", current_position);
                // Give the network a chance to recover
                info!("Waiting for {} seconds before retrying...", retry_delay);
                sleep(Duration::from_secs(retry_delay)).await;
                continue;
            }
        }
    }
    
    Ok(total_bytes)
}

// Create a stream from a file with improved error handling
fn file_to_stream(file_path: PathBuf) -> Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>> {
    info!("Creating stream from file: {:?}", file_path);
    
    match File::open(&file_path) {
        Ok(file) => {
            let file = Arc::new(Mutex::new(file));
            let path_clone = file_path.clone();
            
            Box::pin(stream::unfold((file, 0u64), move |(file_arc, position)| {
                let path = path_clone.clone();
                async move {
                    let mut buffer = vec![0; 64 * 1024]; // 64KB chunks for better performance
                    
                    // Lock the file
                    let mut file_guard = file_arc.lock().await;
                    
                    // Try to seek to the current position first
                    if let Err(e) = file_guard.seek(SeekFrom::Start(position)) {
                        drop(file_guard); // Explicitly drop the guard before returning
                        return Some((Err(anyhow::anyhow!("Failed to seek in file: {}", e)), (file_arc, position)));
                    }
                    
                    // Read the data
                    let read_result = file_guard.read(&mut buffer);
                    
                    // Drop the guard explicitly before continuing
                    drop(file_guard);
                    
                    // Now process the read result
                    match read_result {
                    
                        Ok(n) if n > 0 => {
                            buffer.truncate(n);
                            let new_position = position + n as u64;
                            
                            // Log progress occasionally
                            if new_position % (50 * 1024 * 1024) < (n as u64) { // Log every ~50MB
                                info!("Reading from file: {} MB processed", new_position / (1024 * 1024));
                            }
                            
                            Some((Ok(Bytes::from(buffer)), (file_arc, new_position)))
                        },
                        Ok(_) => {
                            info!("Finished reading file: {:?}", path);
                            None // EOF
                        },
                        Err(e) => {
                            error!("Error reading from file {:?}: {}", path, e);
                            Some((Err(anyhow::anyhow!("Error reading file: {}", e)), (file_arc, position)))
                        },
                    }
                }
            }))
        },
        Err(e) => {
            error!("Failed to open file: {:?} - {}", file_path, e);
            // Return an error stream
            Box::pin(stream::once(async move { Err(anyhow::anyhow!("Failed to open file: {}", e)) }))
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    setup_logging(args.logging_format);

    // Create snapshot directory if it doesn't exist
    if !Path::new(&args.snapshot_dir).exists() {
        std::fs::create_dir_all(&args.snapshot_dir).context("Failed to create snapshot directory")?;
    }

    // Create an HTTP client with increased timeouts for large files
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3600)) // 1 hour timeout
        .connect_timeout(Duration::from_secs(60)) // 60 second connect timeout
        .build()
        .context("Failed to build HTTP client")?;
        
    // Generate a download URL
    let download_url = format!("{}/download", args.snapshot_server_url);
    info!("Download URL: {}", download_url);
    
    // Create temp directory if it doesn't exist
    let temp_dir = std::env::temp_dir().join(&args.snapshot_dir);
    if !temp_dir.exists() {
        std::fs::create_dir_all(&temp_dir).context("Failed to create temp directory")?;
    }
    
    // Check for existing temp files if resume flag is set
    let temp_file_path = if args.resume {
        if let Some((path, size)) = find_largest_temp_file(&args.snapshot_dir) {
            info!("Found existing temp file: {:?} ({} MB)", path, size / (1024 * 1024));
            path
        } else {
            let random_number = rand::random::<u64>();
            temp_dir.join(format!("temp-snapshot-{}", random_number))
        }
    } else {
        let random_number = rand::random::<u64>();
        temp_dir.join(format!("temp-snapshot-{}", random_number))
    };
    
    info!("Using temp file: {:?}", temp_file_path);
    
    // Download with resume capability - with error handling
    let total_bytes = match download_with_resume(
        &http_client, 
        &download_url, 
        &temp_file_path, 
        args.max_retries, 
        args.retry_delay,
        args.chunk_size_kb
    ).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Download error: {}. Checking if we can still use partial file...", e);
            // Check if we have a partial file that's usable
            if temp_file_path.exists() {
                match temp_file_path.metadata() {
                    Ok(metadata) => {
                        let size = metadata.len();
                        if size > 17 { // Minimum size for a valid snapshot (1 byte version + 8 bytes start slot + 8 bytes end slot)
                            info!("Partial download found ({} MB). Attempting to use it...", size / (1024 * 1024));
                            size
                        } else {
                            return Err(anyhow::anyhow!("Download failed and partial file is too small to be usable"));
                        }
                    },
                    Err(_) => return Err(anyhow::anyhow!("Download failed and couldn't check partial file")),
                }
            } else {
                return Err(anyhow::anyhow!("Download failed and no partial file exists"));
            }
        }
    };
    
    info!("Download complete. Total size: {} MB", total_bytes / (1024 * 1024));
    
    // Create a stream from the downloaded file
    let file_stream = file_to_stream(temp_file_path.clone());
    
    let directory_adapter = DirectoryAdapter::from_local_directory(args.snapshot_dir.clone());
    info!("Processing snapshot data...");
    create_snapshot_from_byte_stream(file_stream, &directory_adapter).await?;
    
    // Clean up the temp file after successful processing
    if temp_file_path.exists() {
        if let Err(e) = std::fs::remove_file(&temp_file_path) {
            warn!("Failed to remove temp file: {}", e);
        } else {
            info!("Removed temp file {:?}", temp_file_path);
        }
    }

    info!("Snapshot successfully downloaded and processed");
    Ok(())
}
