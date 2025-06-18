use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use log::warn;
use serde::{Deserialize, Serialize};

use crate::ingester::error::IngesterError;
use crate::ingester::typedefs::block_info::BlockInfo;

pub mod dumper;
pub mod loader;

pub use dumper::BlockDumper;
pub use loader::BlockDumpLoader;

/// Configuration for block dumping
#[derive(Debug, Clone)]
pub struct DumpConfig {
    /// Directory where block dumps will be stored
    pub dump_dir: PathBuf,
    /// Maximum number of blocks per dump file
    pub blocks_per_file: usize,
    /// Whether to compress dump files
    pub compress: bool,
    /// File format for dumps
    pub format: DumpFormat,
}

impl Default for DumpConfig {
    fn default() -> Self {
        Self {
            dump_dir: PathBuf::from("./block_dumps"),
            blocks_per_file: 1000,
            compress: false,
            format: DumpFormat::Json,
        }
    }
}

/// Supported dump file formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpFormat {
    Json,
    Bincode,
}

impl DumpFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            DumpFormat::Json => "json",
            DumpFormat::Bincode => "bin",
        }
    }
}

impl FromStr for DumpFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(DumpFormat::Json),
            "bincode" | "bin" => Ok(DumpFormat::Bincode),
            _ => Err(format!("Invalid dump format: {}", s)),
        }
    }
}

impl std::fmt::Display for DumpFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DumpFormat::Json => write!(f, "json"),
            DumpFormat::Bincode => write!(f, "bincode"),
        }
    }
}

/// Metadata for a dump file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpFileMetadata {
    pub file_path: PathBuf,
    pub start_slot: u64,
    pub end_slot: u64,
    pub block_count: usize,
    pub format: String,
    pub compressed: bool,
    pub created_at: u64, // Unix timestamp
}

/// Represents a batch of blocks to be dumped
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBatch {
    pub blocks: Vec<BlockInfo>,
    pub metadata: BatchMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMetadata {
    pub start_slot: u64,
    pub end_slot: u64,
    pub block_count: usize,
    pub created_at: u64,
}

impl BlockBatch {
    pub fn new(blocks: Vec<BlockInfo>) -> Self {
        let start_slot = blocks.first().map(|b| b.metadata.slot).unwrap_or(0);
        let end_slot = blocks.last().map(|b| b.metadata.slot).unwrap_or(0);
        let block_count = blocks.len();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            blocks,
            metadata: BatchMetadata {
                start_slot,
                end_slot,
                block_count,
                created_at,
            },
        }
    }
}

/// Utility functions for dump operations
pub fn create_dump_filename(start_slot: u64, end_slot: u64, format: DumpFormat) -> String {
    format!(
        "blocks_{:016}_{:016}.{}",
        start_slot,
        end_slot,
        format.extension()
    )
}

pub fn create_metadata_filename(start_slot: u64, end_slot: u64) -> String {
    format!("blocks_{:016}_{:016}.meta", start_slot, end_slot)
}

/// Parse slot range from dump filename
pub fn parse_slot_range_from_filename(filename: &str) -> Option<(u64, u64)> {
    let stem = Path::new(filename).file_stem()?.to_str()?;
    let parts: Vec<&str> = stem.split('_').collect();

    if parts.len() >= 3 && parts[0] == "blocks" {
        let start_slot = parts[1].parse().ok()?;
        let end_slot = parts[2].parse().ok()?;
        Some((start_slot, end_slot))
    } else {
        None
    }
}

/// Get all dump files in a directory, sorted by start slot
pub fn get_dump_files(dump_dir: &Path) -> Result<Vec<DumpFileMetadata>, IngesterError> {
    if !dump_dir.exists() {
        return Ok(Vec::new());
    }

    let mut dump_files = Vec::new();

    for entry in std::fs::read_dir(dump_dir)
        .map_err(|e| IngesterError::IoError(format!("Failed to read dump directory: {}", e)))?
    {
        let entry = entry.map_err(|e| {
            IngesterError::IoError(format!("Failed to read directory entry: {}", e))
        })?;
        let path = entry.path();

        if path.is_file() {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Skip metadata files
            if filename.ends_with(".meta") {
                continue;
            }

            // Try to parse slot range from filename
            if let Some((start_slot, end_slot)) = parse_slot_range_from_filename(filename) {
                let format = if filename.ends_with(".json") {
                    "json"
                } else if filename.ends_with(".bin") {
                    "bincode"
                } else {
                    continue;
                };

                // Try to load metadata file if it exists
                let meta_filename = create_metadata_filename(start_slot, end_slot);
                let meta_path = dump_dir.join(meta_filename);

                let (block_count, created_at, compressed) = if meta_path.exists() {
                    match load_metadata(&meta_path) {
                        Ok(meta) => (meta.block_count, meta.created_at, meta.compressed),
                        Err(e) => {
                            warn!("Failed to load metadata for {}: {}", filename, e);
                            (0, 0, false)
                        }
                    }
                } else {
                    (0, 0, false)
                };

                dump_files.push(DumpFileMetadata {
                    file_path: path,
                    start_slot,
                    end_slot,
                    block_count,
                    format: format.to_string(),
                    compressed,
                    created_at,
                });
            }
        }
    }

    // Sort by start slot
    dump_files.sort_by_key(|f| f.start_slot);

    Ok(dump_files)
}

/// Load metadata from a metadata file
fn load_metadata(meta_path: &Path) -> Result<DumpFileMetadata, IngesterError> {
    let file = File::open(meta_path)
        .map_err(|e| IngesterError::IoError(format!("Failed to open metadata file: {}", e)))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader)
        .map_err(|e| IngesterError::ParseError(format!("Failed to parse metadata: {}", e)))
}

/// Save metadata to a metadata file
pub fn save_metadata(meta_path: &Path, metadata: &DumpFileMetadata) -> Result<(), IngesterError> {
    let file = File::create(meta_path)
        .map_err(|e| IngesterError::IoError(format!("Failed to create metadata file: {}", e)))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, metadata)
        .map_err(|e| IngesterError::IoError(format!("Failed to write metadata: {}", e)))?;
    Ok(())
}

/// Check if dump directory has enough space for new dumps
pub fn check_dump_directory_space(dump_dir: &Path, _required_space_mb: u64) -> bool {
    // This is a simplified check - in production you might want to use statvfs or similar
    match std::fs::metadata(dump_dir) {
        Ok(_) => true,  // Assume we have space if directory exists
        Err(_) => true, // Assume we can create the directory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_dump_filename() {
        let filename = create_dump_filename(1000, 2000, DumpFormat::Json);
        assert_eq!(filename, "blocks_0000000000001000_0000000000002000.json");

        let filename = create_dump_filename(1000, 2000, DumpFormat::Bincode);
        assert_eq!(filename, "blocks_0000000000001000_0000000000002000.bin");
    }

    #[test]
    fn test_parse_slot_range_from_filename() {
        let (start, end) =
            parse_slot_range_from_filename("blocks_0000000000001000_0000000000002000.json")
                .unwrap();
        assert_eq!(start, 1000);
        assert_eq!(end, 2000);

        assert!(parse_slot_range_from_filename("invalid_filename.json").is_none());
    }

    #[test]
    fn test_get_dump_files_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let dump_files = get_dump_files(temp_dir.path()).unwrap();
        assert!(dump_files.is_empty());
    }
}
