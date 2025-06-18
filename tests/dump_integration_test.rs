use std::path::PathBuf;
use tempfile::TempDir;

use photon_indexer::common::typedefs::hash::Hash;
use photon_indexer::ingester::dump::{BlockDumpLoader, BlockDumper, DumpConfig, DumpFormat};
use photon_indexer::ingester::typedefs::block_info::{BlockInfo, BlockMetadata};

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
async fn test_dump_and_load_integration() {
    let temp_dir = TempDir::new().unwrap();
    let dump_dir = temp_dir.path().to_path_buf();

    // Create test blocks
    let test_blocks = vec![
        create_test_block(1000),
        create_test_block(1001),
        create_test_block(1002),
        create_test_block(1003),
        create_test_block(1004),
    ];

    // Test with JSON format
    {
        let config = DumpConfig {
            dump_dir: dump_dir.clone(),
            blocks_per_file: 2,
            compress: false,
            format: DumpFormat::Json,
        };

        let dumper = BlockDumper::new(config).unwrap();

        // Add blocks to dumper
        dumper.add_blocks(test_blocks.clone()).await.unwrap();
        dumper.flush().await.unwrap();

        // Verify files were created
        let stats = dumper.get_stats().await;
        assert_eq!(stats.total_files, 3); // 2+2+1 blocks in 3 files
        assert_eq!(stats.total_blocks_dumped, 5);
    }

    // Test loading
    {
        let loader = BlockDumpLoader::new(dump_dir.clone()).unwrap();
        let loader_stats = loader.get_stats();

        assert_eq!(loader_stats.total_files, 3);
        assert_eq!(loader_stats.total_blocks, 5);

        let (min_slot, max_slot) = loader_stats.slot_range.unwrap();
        assert_eq!(min_slot, 1000);
        assert_eq!(max_slot, 1004);

        // Test loading all blocks
        use futures::StreamExt;
        let stream = loader.create_block_stream();
        let loaded_batches: Vec<Vec<BlockInfo>> = stream.collect().await;

        let mut all_loaded_blocks = Vec::new();
        for batch in loaded_batches {
            all_loaded_blocks.extend(batch);
        }

        assert_eq!(all_loaded_blocks.len(), 5);

        // Verify block data
        for (original, loaded) in test_blocks.iter().zip(all_loaded_blocks.iter()) {
            assert_eq!(original.metadata.slot, loaded.metadata.slot);
            assert_eq!(original.metadata.parent_slot, loaded.metadata.parent_slot);
            assert_eq!(original.metadata.block_time, loaded.metadata.block_time);
        }
    }

    // Test range loading
    {
        let loader = BlockDumpLoader::new(dump_dir.clone()).unwrap();

        use futures::StreamExt;
        let stream = loader.create_block_stream_in_range(1001, 1003);
        let loaded_batches: Vec<Vec<BlockInfo>> = stream.collect().await;

        let mut range_blocks = Vec::new();
        for batch in loaded_batches {
            range_blocks.extend(batch);
        }

        // Should have 3 blocks: 1001, 1002, 1003
        assert_eq!(range_blocks.len(), 3);
        assert_eq!(range_blocks[0].metadata.slot, 1001);
        assert_eq!(range_blocks[2].metadata.slot, 1003);
    }

    // Test validation
    {
        let loader = BlockDumpLoader::new(dump_dir.clone()).unwrap();
        let validation = loader.validate_dump_files().unwrap();

        assert_eq!(validation.valid_files, 3);
        assert!(validation.invalid_files.is_empty());
        assert!(validation.is_valid());
    }
}

#[tokio::test]
async fn test_bincode_format() {
    let temp_dir = TempDir::new().unwrap();
    let dump_dir = temp_dir.path().to_path_buf();

    let test_blocks = vec![create_test_block(2000), create_test_block(2001)];

    // Test with Bincode format
    let config = DumpConfig {
        dump_dir: dump_dir.clone(),
        blocks_per_file: 2,
        compress: false,
        format: DumpFormat::Bincode,
    };

    let dumper = BlockDumper::new(config).unwrap();
    dumper.add_blocks(test_blocks.clone()).await.unwrap();
    dumper.flush().await.unwrap();

    // Load back
    let loader = BlockDumpLoader::new(dump_dir).unwrap();

    use futures::StreamExt;
    let stream = loader.create_block_stream();
    let loaded_batches: Vec<Vec<BlockInfo>> = stream.collect().await;

    let mut all_loaded_blocks = Vec::new();
    for batch in loaded_batches {
        all_loaded_blocks.extend(batch);
    }

    assert_eq!(all_loaded_blocks.len(), 2);
    assert_eq!(all_loaded_blocks[0].metadata.slot, 2000);
    assert_eq!(all_loaded_blocks[1].metadata.slot, 2001);
}

#[tokio::test]
async fn test_empty_dump_directory() {
    let temp_dir = TempDir::new().unwrap();
    let dump_dir = temp_dir.path().to_path_buf();

    let loader = BlockDumpLoader::new(dump_dir).unwrap();
    let stats = loader.get_stats();

    assert_eq!(stats.total_files, 0);
    assert_eq!(stats.total_blocks, 0);
    assert!(stats.slot_range.is_none());

    // Empty stream should yield no items
    use futures::StreamExt;
    let stream = loader.create_block_stream();
    let loaded_batches: Vec<Vec<BlockInfo>> = stream.collect().await;
    assert!(loaded_batches.is_empty());
}

#[tokio::test]
async fn test_dumper_stats() {
    let temp_dir = TempDir::new().unwrap();
    let dump_dir = temp_dir.path().to_path_buf();

    let config = DumpConfig {
        dump_dir,
        blocks_per_file: 3,
        compress: false,
        format: DumpFormat::Json,
    };

    let dumper = BlockDumper::new(config).unwrap();

    // Initially no stats
    let stats = dumper.get_stats().await;
    assert_eq!(stats.total_files, 0);
    assert_eq!(stats.total_blocks_dumped, 0);
    assert_eq!(stats.blocks_in_current_batch, 0);

    // Add some blocks (less than batch size)
    let blocks = vec![create_test_block(1000), create_test_block(1001)];
    dumper.add_blocks(blocks).await.unwrap();

    let stats = dumper.get_stats().await;
    assert_eq!(stats.total_files, 0); // No files dumped yet
    assert_eq!(stats.total_blocks_dumped, 0);
    assert_eq!(stats.blocks_in_current_batch, 2);

    // Add one more block to trigger dump
    let blocks = vec![create_test_block(1002)];
    dumper.add_blocks(blocks).await.unwrap();

    let stats = dumper.get_stats().await;
    assert_eq!(stats.total_files, 1); // One file dumped
    assert_eq!(stats.total_blocks_dumped, 3);
    assert_eq!(stats.blocks_in_current_batch, 0);
}
