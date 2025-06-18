use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;

use log::info;
use serde_json;
use tokio::sync::Mutex;

use crate::ingester::error::IngesterError;
use crate::ingester::typedefs::block_info::BlockInfo;

use super::{
    create_dump_filename, create_metadata_filename, save_metadata, BlockBatch, DumpConfig,
    DumpFileMetadata, DumpFormat,
};

/// Block dumper for writing blocks to files
pub struct BlockDumper {
    pub config: DumpConfig,
    current_batch: Arc<Mutex<Vec<BlockInfo>>>,
    files_written: Arc<Mutex<Vec<DumpFileMetadata>>>,
}

impl BlockDumper {
    pub fn new(config: DumpConfig) -> Result<Self, IngesterError> {
        // Create dump directory if it doesn't exist
        if !config.dump_dir.exists() {
            create_dir_all(&config.dump_dir).map_err(|e| {
                IngesterError::IoError(format!(
                    "Failed to create dump directory {:?}: {}",
                    config.dump_dir, e
                ))
            })?;
            info!("Created dump directory: {:?}", config.dump_dir);
        }

        Ok(Self {
            config,
            current_batch: Arc::new(Mutex::new(Vec::new())),
            files_written: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Add blocks to the current batch and dump if batch is full
    pub async fn add_blocks(&self, blocks: Vec<BlockInfo>) -> Result<(), IngesterError> {
        let mut current_batch = self.current_batch.lock().await;

        for block in blocks {
            current_batch.push(block);

            // Check if we need to dump the current batch
            if current_batch.len() >= self.config.blocks_per_file {
                let batch_to_dump = current_batch.drain(..).collect();
                drop(current_batch); // Release the lock before dumping

                self.dump_batch(batch_to_dump).await?;
                current_batch = self.current_batch.lock().await;
            }
        }

        Ok(())
    }

    /// Dump any remaining blocks in the current batch
    pub async fn flush(&self) -> Result<(), IngesterError> {
        let mut current_batch = self.current_batch.lock().await;

        if !current_batch.is_empty() {
            let batch_to_dump = current_batch.drain(..).collect();
            drop(current_batch);

            self.dump_batch(batch_to_dump).await?;
        }

        Ok(())
    }

    /// Dump a batch of blocks to a file
    async fn dump_batch(&self, blocks: Vec<BlockInfo>) -> Result<(), IngesterError> {
        if blocks.is_empty() {
            return Ok(());
        }

        let batch = BlockBatch::new(blocks);
        let start_slot = batch.metadata.start_slot;
        let end_slot = batch.metadata.end_slot;
        let block_count = batch.metadata.block_count;

        // Create filenames
        let dump_filename = create_dump_filename(start_slot, end_slot, self.config.format);
        let meta_filename = create_metadata_filename(start_slot, end_slot);

        let dump_path = self.config.dump_dir.join(&dump_filename);
        let meta_path = self.config.dump_dir.join(&meta_filename);

        // Write the dump file
        self.write_dump_file(&dump_path, &batch).await?;

        // Create and save metadata
        let metadata = DumpFileMetadata {
            file_path: dump_path.clone(),
            start_slot,
            end_slot,
            block_count,
            format: match self.config.format {
                DumpFormat::Json => "json".to_string(),
                DumpFormat::Bincode => "bincode".to_string(),
            },
            compressed: self.config.compress,
            created_at: batch.metadata.created_at,
        };

        save_metadata(&meta_path, &metadata)?;

        // Add to files written list
        let mut files_written = self.files_written.lock().await;
        files_written.push(metadata);

        info!(
            "Dumped {} blocks (slots {}-{}) to {}",
            block_count, start_slot, end_slot, dump_filename
        );

        Ok(())
    }

    /// Write blocks to dump file based on format
    async fn write_dump_file(
        &self,
        dump_path: &Path,
        batch: &BlockBatch,
    ) -> Result<(), IngesterError> {
        let file = File::create(dump_path).map_err(|e| {
            IngesterError::IoError(format!("Failed to create dump file {:?}: {}", dump_path, e))
        })?;

        let mut writer = BufWriter::new(file);

        match self.config.format {
            DumpFormat::Json => {
                serde_json::to_writer_pretty(&mut writer, batch).map_err(|e| {
                    IngesterError::IoError(format!("Failed to write JSON dump: {}", e))
                })?;
            }
            DumpFormat::Bincode => {
                bincode::serialize_into(&mut writer, batch).map_err(|e| {
                    IngesterError::IoError(format!("Failed to write bincode dump: {}", e))
                })?;
            }
        }

        writer
            .flush()
            .map_err(|e| IngesterError::IoError(format!("Failed to flush dump file: {}", e)))?;

        Ok(())
    }

    /// Get list of all files written by this dumper
    pub async fn get_written_files(&self) -> Vec<DumpFileMetadata> {
        let files_written = self.files_written.lock().await;
        files_written.clone()
    }

    /// Clear the list of written files
    pub async fn clear_written_files(&self) {
        let mut files_written = self.files_written.lock().await;
        files_written.clear();
    }

    /// Get dump statistics
    pub async fn get_stats(&self) -> DumpStats {
        let files_written = self.files_written.lock().await;
        let current_batch = self.current_batch.lock().await;

        let total_files = files_written.len();
        let total_blocks_dumped = files_written.iter().map(|f| f.block_count).sum();
        let blocks_in_current_batch = current_batch.len();

        DumpStats {
            total_files,
            total_blocks_dumped,
            blocks_in_current_batch,
        }
    }
}

/// Statistics for block dumping
#[derive(Debug, Clone)]
pub struct DumpStats {
    pub total_files: usize,
    pub total_blocks_dumped: usize,
    pub blocks_in_current_batch: usize,
}

impl DumpStats {
    pub fn total_blocks(&self) -> usize {
        self.total_blocks_dumped + self.blocks_in_current_batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::typedefs::hash::Hash;
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
    async fn test_block_dumper_basic() {
        let temp_dir = TempDir::new().unwrap();
        let config = DumpConfig {
            dump_dir: temp_dir.path().to_path_buf(),
            blocks_per_file: 2,
            compress: false,
            format: DumpFormat::Json,
        };

        let dumper = BlockDumper::new(config).unwrap();

        // Add some blocks
        let blocks = vec![create_test_block(1000), create_test_block(1001)];
        dumper.add_blocks(blocks).await.unwrap();

        // Should have created a dump file since we reached blocks_per_file
        let stats = dumper.get_stats().await;
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_blocks_dumped, 2);
        assert_eq!(stats.blocks_in_current_batch, 0);
    }

    #[tokio::test]
    async fn test_block_dumper_flush() {
        let temp_dir = TempDir::new().unwrap();
        let config = DumpConfig {
            dump_dir: temp_dir.path().to_path_buf(),
            blocks_per_file: 10, // Large batch size
            compress: false,
            format: DumpFormat::Json,
        };

        let dumper = BlockDumper::new(config).unwrap();

        // Add some blocks (less than blocks_per_file)
        let blocks = vec![create_test_block(1000), create_test_block(1001)];
        dumper.add_blocks(blocks).await.unwrap();

        // Should not have dumped yet
        let stats = dumper.get_stats().await;
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.blocks_in_current_batch, 2);

        // Flush should dump the remaining blocks
        dumper.flush().await.unwrap();

        let stats = dumper.get_stats().await;
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_blocks_dumped, 2);
        assert_eq!(stats.blocks_in_current_batch, 0);
    }
}
