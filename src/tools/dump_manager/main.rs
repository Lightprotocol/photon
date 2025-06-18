use std::path::PathBuf;

use clap::{Parser, Subcommand};
use photon_indexer::ingester::dump::{get_dump_files, BlockDumpLoader};

/// Block dump manager CLI tool
#[derive(Parser, Debug)]
#[command(version, about = "Manage Photon block dump files")]
struct Args {
    /// Command to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List dump files in a directory
    List {
        /// Directory containing dump files
        #[arg(short, long)]
        dump_dir: String,

        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },
    /// Validate dump files
    Validate {
        /// Directory containing dump files
        #[arg(short, long)]
        dump_dir: String,
    },
    /// Show statistics about dump files
    Stats {
        /// Directory containing dump files
        #[arg(short, long)]
        dump_dir: String,
    },
    /// Show information about a specific slot range
    Range {
        /// Directory containing dump files
        #[arg(short, long)]
        dump_dir: String,

        /// Start slot
        #[arg(short, long)]
        start_slot: u64,

        /// End slot
        #[arg(short, long)]
        end_slot: u64,
    },
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    match args.command {
        Commands::List { dump_dir, verbose } => {
            list_dumps(&dump_dir, verbose).await;
        }
        Commands::Validate { dump_dir } => {
            validate_dumps(&dump_dir).await;
        }
        Commands::Stats { dump_dir } => {
            show_stats(&dump_dir).await;
        }
        Commands::Range {
            dump_dir,
            start_slot,
            end_slot,
        } => {
            show_range_info(&dump_dir, start_slot, end_slot).await;
        }
    }
}

async fn list_dumps(dump_dir: &str, verbose: bool) {
    let dump_path = PathBuf::from(dump_dir);

    match get_dump_files(&dump_path) {
        Ok(dump_files) => {
            if dump_files.is_empty() {
                println!("No dump files found in directory: {}", dump_dir);
                return;
            }

            println!(
                "Found {} dump files in directory: {}",
                dump_files.len(),
                dump_dir
            );
            println!();

            if verbose {
                println!(
                    "{:<20} {:<20} {:<10} {:<10} {:<15} {}",
                    "Start Slot", "End Slot", "Blocks", "Format", "Size (MB)", "File"
                );
                println!("{}", "-".repeat(100));

                for file in &dump_files {
                    let file_size = std::fs::metadata(&file.file_path)
                        .map(|m| m.len() as f64 / 1024.0 / 1024.0)
                        .unwrap_or(0.0);

                    println!(
                        "{:<20} {:<20} {:<10} {:<10} {:<15.2} {}",
                        file.start_slot,
                        file.end_slot,
                        file.block_count,
                        file.format,
                        file_size,
                        file.file_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                    );
                }
            } else {
                for file in &dump_files {
                    println!(
                        "Slots {}-{}: {} blocks ({})",
                        file.start_slot, file.end_slot, file.block_count, file.format
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("Error listing dump files: {}", e);
            std::process::exit(1);
        }
    }
}

async fn validate_dumps(dump_dir: &str) {
    let dump_path = PathBuf::from(dump_dir);

    match BlockDumpLoader::new(dump_path) {
        Ok(loader) => {
            println!("Validating dump files in directory: {}", dump_dir);

            match loader.validate_dump_files() {
                Ok(validation) => {
                    println!("Validation Results:");
                    println!("- Valid files: {}", validation.valid_files);

                    if !validation.invalid_files.is_empty() {
                        println!("- Invalid files: {}", validation.invalid_files.len());
                        for (path, error) in &validation.invalid_files {
                            println!("  - {:?}: {}", path.file_name().unwrap_or_default(), error);
                        }
                    }

                    if !validation.missing_slots.is_empty() {
                        println!("- Missing slots: {} slots", validation.missing_slots.len());
                        if validation.missing_slots.len() <= 10 {
                            println!("  - {:?}", validation.missing_slots);
                        } else {
                            println!("  - First 10: {:?}", &validation.missing_slots[..10]);
                        }
                    }

                    if !validation.duplicate_slots.is_empty() {
                        println!(
                            "- Duplicate slots: {} slots",
                            validation.duplicate_slots.len()
                        );
                        if validation.duplicate_slots.len() <= 10 {
                            println!("  - {:?}", validation.duplicate_slots);
                        } else {
                            println!("  - First 10: {:?}", &validation.duplicate_slots[..10]);
                        }
                    }

                    if validation.is_valid() {
                        println!("\n✅ All dump files are valid!");
                    } else {
                        println!("\n❌ Some issues found with dump files.");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error during validation: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Error creating dump loader: {}", e);
            std::process::exit(1);
        }
    }
}

async fn show_stats(dump_dir: &str) {
    let dump_path = PathBuf::from(dump_dir);

    match BlockDumpLoader::new(dump_path) {
        Ok(loader) => {
            let stats = loader.get_stats();

            println!("Dump Directory Statistics:");
            println!("- Directory: {}", dump_dir);
            println!("- Total files: {}", stats.total_files);
            println!("- Total blocks: {}", stats.total_blocks);

            if let Some((min_slot, max_slot)) = stats.slot_range {
                println!("- Slot range: {} to {}", min_slot, max_slot);
                println!("- Total slots covered: {}", max_slot - min_slot + 1);
            } else {
                println!("- No slot range available");
            }

            // Calculate total file size
            let mut total_size_bytes = 0u64;
            for file in loader.get_dump_files() {
                if let Ok(metadata) = std::fs::metadata(&file.file_path) {
                    total_size_bytes += metadata.len();
                }
            }

            let total_size_mb = total_size_bytes as f64 / 1024.0 / 1024.0;
            let total_size_gb = total_size_mb / 1024.0;

            if total_size_gb > 1.0 {
                println!("- Total size: {:.2} GB", total_size_gb);
            } else {
                println!("- Total size: {:.2} MB", total_size_mb);
            }

            if stats.total_blocks > 0 {
                let avg_blocks_per_file = stats.total_blocks as f64 / stats.total_files as f64;
                println!("- Average blocks per file: {:.1}", avg_blocks_per_file);
            }
        }
        Err(e) => {
            eprintln!("Error loading dump directory: {}", e);
            std::process::exit(1);
        }
    }
}

async fn show_range_info(dump_dir: &str, start_slot: u64, end_slot: u64) {
    let dump_path = PathBuf::from(dump_dir);

    match BlockDumpLoader::new(dump_path) {
        Ok(loader) => {
            let files_in_range = loader.get_dump_files_in_range(start_slot, end_slot);

            println!("Files covering slot range {} to {}:", start_slot, end_slot);

            if files_in_range.is_empty() {
                println!("No dump files found covering this range.");
                return;
            }

            let mut total_blocks = 0;
            let mut total_size_bytes = 0u64;

            println!(
                "{:<20} {:<20} {:<10} {:<10} {:<15} {}",
                "Start Slot", "End Slot", "Blocks", "Format", "Size (MB)", "File"
            );
            println!("{}", "-".repeat(100));

            for file in &files_in_range {
                let file_size = std::fs::metadata(&file.file_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                total_size_bytes += file_size;

                let file_size_mb = file_size as f64 / 1024.0 / 1024.0;

                // Count blocks that actually fall in the requested range
                let blocks_in_range = if file.start_slot >= start_slot && file.end_slot <= end_slot
                {
                    file.block_count
                } else {
                    // This is an approximation - actual count would require loading the file
                    let overlap_start = file.start_slot.max(start_slot);
                    let overlap_end = file.end_slot.min(end_slot);
                    let overlap_slots = overlap_end - overlap_start + 1;
                    let total_slots = file.end_slot - file.start_slot + 1;
                    ((overlap_slots as f64 / total_slots as f64) * file.block_count as f64) as usize
                };

                total_blocks += blocks_in_range;

                println!(
                    "{:<20} {:<20} {:<10} {:<10} {:<15.2} {}",
                    file.start_slot,
                    file.end_slot,
                    blocks_in_range,
                    file.format,
                    file_size_mb,
                    file.file_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                );
            }

            println!();
            println!("Summary:");
            println!("- Files in range: {}", files_in_range.len());
            println!("- Estimated blocks in range: {}", total_blocks);

            let total_size_mb = total_size_bytes as f64 / 1024.0 / 1024.0;
            if total_size_mb > 1024.0 {
                println!("- Total size: {:.2} GB", total_size_mb / 1024.0);
            } else {
                println!("- Total size: {:.2} MB", total_size_mb);
            }
        }
        Err(e) => {
            eprintln!("Error loading dump directory: {}", e);
            std::process::exit(1);
        }
    }
}
