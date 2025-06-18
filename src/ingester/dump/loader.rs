use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::pin::Pin;

use async_stream::stream;
use futures::Stream;
use log::{debug, error, info, warn};
use serde_json;

use crate::ingester::error::IngesterError;
use crate::ingester::typedefs::block_info::BlockInfo;

use super::{get_dump_files, BlockBatch, DumpFileMetadata, DumpFormat};

/// Block dump loader for reading blocks from dump files
pub struct BlockDumpLoader {
    dump_dir: PathBuf,
    dump_files: Vec<DumpFileMetadata>,
}

impl BlockDumpLoader {
    /// Create a new BlockDumpLoader from a dump directory
    pub fn new(dump_dir: PathBuf) -> Result<Self, IngesterError> {
        if !dump_dir.exists() {
            return Err(IngesterError::IoError(format!(
                "Dump directory does not exist: {:?}",
                dump_dir
            )));
        }

        let dump_files = get_dump_files(&dump_dir)?;

        if dump_files.is_empty() {
            warn!("No dump files found in directory: {:?}", dump_dir);
        } else {
            info!(
                "Found {} dump files in directory: {:?}",
                dump_files.len(),
                dump_dir
            );
        }

        Ok(Self {
            dump_dir,
            dump_files,
        })
    }

    /// Get all available dump files
    pub fn get_dump_files(&self) -> &[DumpFileMetadata] {
        &self.dump_files
    }

    /// Get dump files within a specific slot range
    pub fn get_dump_files_in_range(
        &self,
        start_slot: u64,
        end_slot: u64,
    ) -> Vec<&DumpFileMetadata> {
        self.dump_files
            .iter()
            .filter(|file| {
                // Include file if it overlaps with the requested range
                file.start_slot <= end_slot && file.end_slot >= start_slot
            })
            .collect()
    }

    /// Load a single dump file and return the blocks
    pub fn load_dump_file(
        &self,
        file_metadata: &DumpFileMetadata,
    ) -> Result<Vec<BlockInfo>, IngesterError> {
        let file_path = &file_metadata.file_path;

        debug!("Loading dump file: {:?}", file_path);

        let file = File::open(file_path).map_err(|e| {
            IngesterError::IoError(format!("Failed to open dump file {:?}: {}", file_path, e))
        })?;

        let reader = BufReader::new(file);
        let batch = match file_metadata.format.as_str() {
            "json" => serde_json::from_reader(reader).map_err(|e| {
                IngesterError::ParseError(format!("Failed to parse JSON dump file: {}", e))
            })?,
            "bincode" => bincode::deserialize_from(reader).map_err(|e| {
                IngesterError::ParseError(format!("Failed to parse bincode dump file: {}", e))
            })?,
            format => {
                return Err(IngesterError::ParseError(format!(
                    "Unsupported dump file format: {}",
                    format
                )));
            }
        };

        let batch: BlockBatch = batch;

        debug!(
            "Loaded {} blocks from dump file (slots {}-{})",
            batch.blocks.len(),
            batch.metadata.start_slot,
            batch.metadata.end_slot
        );

        Ok(batch.blocks)
    }

    /// Create a stream of blocks from all dump files
    pub fn create_block_stream(&self) -> Pin<Box<dyn Stream<Item = Vec<BlockInfo>> + Send + '_>> {
        let stream = stream! {
            for file_metadata in &self.dump_files {
                match self.load_dump_file(file_metadata) {
                    Ok(blocks) => {
                        info!(
                            "Loaded {} blocks from dump file: {:?}",
                            blocks.len(),
                            file_metadata.file_path.file_name().unwrap_or_default()
                        );
                        yield blocks;
                    }
                    Err(e) => {
                        error!(
                            "Failed to load dump file {:?}: {}",
                            file_metadata.file_path, e
                        );
                        // Continue with next file instead of stopping the entire stream
                    }
                }
            }
        };
        Box::pin(stream)
    }

    /// Create a stream of blocks from dump files within a specific slot range
    pub fn create_block_stream_in_range(
        &self,
        start_slot: u64,
        end_slot: u64,
    ) -> Pin<Box<dyn Stream<Item = Vec<BlockInfo>> + Send + '_>> {
        let files_in_range = self.get_dump_files_in_range(start_slot, end_slot);

        let stream = stream! {
            for file_metadata in files_in_range {
                match self.load_dump_file(file_metadata) {
                    Ok(mut blocks) => {
                        // Filter blocks to only include those in the requested range
                        blocks.retain(|block| {
                            block.metadata.slot >= start_slot && block.metadata.slot <= end_slot
                        });

                        if !blocks.is_empty() {
                            info!(
                                "Loaded {} blocks (filtered to range {}-{}) from dump file: {:?}",
                                blocks.len(),
                                start_slot,
                                end_slot,
                                file_metadata.file_path.file_name().unwrap_or_default()
                            );
                            yield blocks;
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to load dump file {:?}: {}",
                            file_metadata.file_path, e
                        );
                        // Continue with next file instead of stopping the entire stream
                    }
                }
            }
        };
        Box::pin(stream)
    }

    /// Get the total slot range covered by all dump files
    pub fn get_total_slot_range(&self) -> Option<(u64, u64)> {
        if self.dump_files.is_empty() {
            return None;
        }

        let min_slot = self.dump_files.iter().map(|f| f.start_slot).min()?;
        let max_slot = self.dump_files.iter().map(|f| f.end_slot).max()?;

        Some((min_slot, max_slot))
    }

    /// Get statistics about the dump files
    pub fn get_stats(&self) -> LoaderStats {
        let total_files = self.dump_files.len();
        let total_blocks = self.dump_files.iter().map(|f| f.block_count).sum();
        let slot_range = self.get_total_slot_range();

        LoaderStats {
            total_files,
            total_blocks,
            slot_range,
        }
    }

    /// Validate dump files for consistency
    pub fn validate_dump_files(&self) -> Result<ValidationResult, IngesterError> {
        let mut validation_result = ValidationResult {
            valid_files: 0,
            invalid_files: Vec::new(),
            missing_slots: Vec::new(),
            duplicate_slots: Vec::new(),
        };

        // Check each file individually
        for file_metadata in &self.dump_files {
            match self.validate_single_file(file_metadata) {
                Ok(()) => validation_result.valid_files += 1,
                Err(e) => validation_result
                    .invalid_files
                    .push((file_metadata.file_path.clone(), e.to_string())),
            }
        }

        // Check for gaps and overlaps in slot coverage
        let mut all_slots: Vec<u64> = Vec::new();
        for file_metadata in &self.dump_files {
            for slot in file_metadata.start_slot..=file_metadata.end_slot {
                all_slots.push(slot);
            }
        }

        all_slots.sort();

        // Find duplicates
        let mut prev_slot = None;
        for &slot in &all_slots {
            if let Some(prev) = prev_slot {
                if slot == prev {
                    if !validation_result.duplicate_slots.contains(&slot) {
                        validation_result.duplicate_slots.push(slot);
                    }
                }
            }
            prev_slot = Some(slot);
        }

        // Find gaps (this is a simplified check)
        if let Some((min_slot, _max_slot)) = self.get_total_slot_range() {
            let mut expected_slot = min_slot;
            for &slot in &all_slots {
                if slot > expected_slot {
                    for missing in expected_slot..slot {
                        validation_result.missing_slots.push(missing);
                    }
                }
                expected_slot = slot + 1;
            }
        }

        Ok(validation_result)
    }

    /// Validate a single dump file
    fn validate_single_file(&self, file_metadata: &DumpFileMetadata) -> Result<(), IngesterError> {
        // Check if file exists
        if !file_metadata.file_path.exists() {
            return Err(IngesterError::IoError(format!(
                "Dump file does not exist: {:?}",
                file_metadata.file_path
            )));
        }

        // Try to load the file to check if it's readable
        let _blocks = self.load_dump_file(file_metadata)?;

        Ok(())
    }
}

/// Statistics about loaded dump files
#[derive(Debug, Clone)]
pub struct LoaderStats {
    pub total_files: usize,
    pub total_blocks: usize,
    pub slot_range: Option<(u64, u64)>,
}

/// Result of dump file validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid_files: usize,
    pub invalid_files: Vec<(PathBuf, String)>,
    pub missing_slots: Vec<u64>,
    pub duplicate_slots: Vec<u64>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.invalid_files.is_empty()
            && self.missing_slots.is_empty()
            && self.duplicate_slots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::typedefs::hash::Hash;
    use crate::ingester::dump::{BlockDumper, DumpConfig};
    use crate::ingester::typedefs::block_info::{BlockInfo, BlockMetadata};
    use tempfile::TempDir;

    fn create_test_block(slot: u64) -> BlockInfo {
        BlockInfo {
            metadata: BlockMetadata {
                slot,
                parent_slot: slot.saturating_sub(1),
                block_time: 1000000000 + slot as i64,
                blockhash: Hash::default(),
                parent_blockhash: Hash::default(),
                block_height: slot,
            },
            transactions: vec![],
        }
    }

    #[tokio::test]
    async fn test_block_dump_loader_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let loader = BlockDumpLoader::new(temp_dir.path().to_path_buf()).unwrap();

        assert_eq!(loader.get_dump_files().len(), 0);
        assert_eq!(loader.get_stats().total_files, 0);
        assert_eq!(loader.get_stats().total_blocks, 0);
        assert!(loader.get_total_slot_range().is_none());
    }

    #[tokio::test]
    async fn test_block_dump_loader_with_dumps() {
        let temp_dir = TempDir::new().unwrap();

        // Create some dump files using BlockDumper
        let config = DumpConfig {
            dump_dir: temp_dir.path().to_path_buf(),
            blocks_per_file: 2,
            compress: false,
            format: DumpFormat::Json,
        };

        let dumper = BlockDumper::new(config).unwrap();

        // Add blocks in two batches
        let blocks1 = vec![create_test_block(1000), create_test_block(1001)];
        let blocks2 = vec![create_test_block(1002), create_test_block(1003)];

        dumper.add_blocks(blocks1).await.unwrap();
        dumper.add_blocks(blocks2).await.unwrap();

        // Now test the loader
        let loader = BlockDumpLoader::new(temp_dir.path().to_path_buf()).unwrap();

        assert_eq!(loader.get_dump_files().len(), 2);

        let stats = loader.get_stats();
        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.total_blocks, 4);

        let (min_slot, max_slot) = loader.get_total_slot_range().unwrap();
        assert_eq!(min_slot, 1000);
        assert_eq!(max_slot, 1003);
    }

    #[tokio::test]
    async fn test_block_dump_loader_stream() {
        let temp_dir = TempDir::new().unwrap();

        // Create some dump files
        let config = DumpConfig {
            dump_dir: temp_dir.path().to_path_buf(),
            blocks_per_file: 2,
            compress: false,
            format: DumpFormat::Json,
        };

        let dumper = BlockDumper::new(config).unwrap();
        let blocks = vec![create_test_block(1000), create_test_block(1001)];
        dumper.add_blocks(blocks).await.unwrap();

        // Test the stream
        let loader = BlockDumpLoader::new(temp_dir.path().to_path_buf()).unwrap();
        let stream = loader.create_block_stream();

        use futures::StreamExt;
        let collected_blocks: Vec<Vec<BlockInfo>> = stream.collect().await;

        assert_eq!(collected_blocks.len(), 1);
        assert_eq!(collected_blocks[0].len(), 2);
        assert_eq!(collected_blocks[0][0].metadata.slot, 1000);
        assert_eq!(collected_blocks[0][1].metadata.slot, 1001);
    }
}
