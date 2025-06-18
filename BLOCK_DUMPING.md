# Block Dumping and Loading Features

This document describes the block dumping and loading features added to Photon, which allow you to:

1. **Dump blocks to files during indexing** - Save blocks to disk as they are being indexed
2. **Reindex from dumped files** - Load and reindex blocks from previously saved dump files

## Features Overview

### Block Dumping
- Save blocks to disk during the indexing process
- Configurable batch sizes and file formats
- Supports JSON and Bincode formats
- Automatic file naming with slot ranges
- Metadata files for each dump

### Block Loading
- Load blocks from dump files for reindexing
- Support for loading specific slot ranges
- Validation of dump file integrity
- Stream-based loading for memory efficiency

## Usage

### Enable Block Dumping During Indexing

To enable block dumping while running the indexer:

```bash
# Basic usage - dumps to ./block_dumps directory
photon --enable-block-dump

# Specify custom dump directory
photon --enable-block-dump --dump-dir /path/to/dumps

# Configure batch size (blocks per file)
photon --enable-block-dump --blocks-per-dump-file 500

# Use bincode format instead of JSON
photon --enable-block-dump --dump-format bincode
```

### Load Blocks from Dump Files

To reindex from previously dumped blocks:

```bash
# Load all blocks from dump directory
photon --load-from-dumps /path/to/dumps

# Load specific slot range
photon --load-from-dumps /path/to/dumps --dump-start-slot 1000000 --dump-end-slot 2000000
```

### Managing Dump Files

Use the `photon-dump-manager` tool to manage dump files:

```bash
# List all dump files in a directory
photon-dump-manager list --dump-dir /path/to/dumps

# Show detailed information
photon-dump-manager list --dump-dir /path/to/dumps --verbose

# Validate dump files
photon-dump-manager validate --dump-dir /path/to/dumps

# Show statistics
photon-dump-manager stats --dump-dir /path/to/dumps

# Show files covering a specific slot range
photon-dump-manager range --dump-dir /path/to/dumps --start-slot 1000000 --end-slot 2000000
```

## File Format

### Dump Files

Dump files are named using the pattern: `blocks_{start_slot:016}_{end_slot:016}.{extension}`

Examples:
- `blocks_0000000000001000_0000000000001999.json`
- `blocks_0000000000002000_0000000000002999.bin`

### Metadata Files

Each dump file has a corresponding metadata file with the `.meta` extension:
- `blocks_0000000000001000_0000000000001999.meta`

Metadata contains:
```json
{
  "file_path": "/path/to/blocks_0000000000001000_0000000000001999.json",
  "start_slot": 1000,
  "end_slot": 1999,
  "block_count": 1000,
  "format": "json",
  "compressed": false,
  "created_at": 1703123456
}
```

### File Contents

JSON format example:
```json
{
  "blocks": [
    {
      "metadata": {
        "slot": 1000,
        "parent_slot": 999,
        "block_time": 1703123456,
        "blockhash": "...",
        "parent_blockhash": "...",
        "block_height": 1000
      },
      "transactions": [...]
    }
  ],
  "metadata": {
    "start_slot": 1000,
    "end_slot": 1999,
    "block_count": 1000,
    "created_at": 1703123456
  }
}
```

## Configuration Options

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--enable-block-dump` | Enable block dumping | false |
| `--dump-dir` | Directory for dump files | `./block_dumps` |
| `--blocks-per-dump-file` | Blocks per dump file | 1000 |
| `--dump-format` | Format (json/bincode) | json |
| `--load-from-dumps` | Load from dump directory | None |
| `--dump-start-slot` | Start slot for loading | None |
| `--dump-end-slot` | End slot for loading | None |

### File Formats

- **JSON**: Human-readable, larger file size, slower I/O
- **Bincode**: Binary format, smaller file size, faster I/O

## Use Cases

### 1. Backup and Recovery
```bash
# Create backups while indexing
photon --enable-block-dump --dump-dir /backup/blocks

# Restore from backup
photon --load-from-dumps /backup/blocks
```

### 2. Development and Testing
```bash
# Dump blocks during development
photon --enable-block-dump --blocks-per-dump-file 100

# Test with specific slot ranges
photon --load-from-dumps ./block_dumps --dump-start-slot 1000 --dump-end-slot 2000
```

### 3. Data Migration
```bash
# Export blocks in different format
photon --enable-block-dump --dump-format bincode --dump-dir /export

# Import to new system
photon --load-from-dumps /export
```

### 4. Parallel Processing
```bash
# Process different slot ranges in parallel
photon --load-from-dumps /dumps --dump-start-slot 1000000 --dump-end-slot 1500000 &
photon --load-from-dumps /dumps --dump-start-slot 1500001 --dump-end-slot 2000000 &
```

## Performance Considerations

### Dumping Performance
- JSON format is slower but human-readable
- Bincode format is faster and more compact
- Larger batch sizes reduce file count but increase memory usage
- Consider disk I/O when setting batch sizes

### Loading Performance
- Loading from local disk is faster than RPC
- Bincode format loads faster than JSON
- Use specific slot ranges to avoid loading unnecessary data
- Stream-based loading minimizes memory usage

## Storage Requirements

### Estimation
Block dump sizes vary based on:
- Transaction count per block
- Instruction complexity
- File format chosen

Rough estimates:
- JSON format: ~100KB - 1MB per block
- Bincode format: ~50KB - 500KB per block

### Disk Space Management
```bash
# Check disk usage
du -sh /path/to/dumps

# Monitor while dumping
watch "du -sh /path/to/dumps && ls -la /path/to/dumps | wc -l"
```

## Error Handling

The system includes robust error handling:
- Failed dumps don't stop indexing
- Invalid dump files are skipped during loading
- Validation tools help identify issues
- Detailed error messages for troubleshooting

## Best Practices

1. **Choose appropriate batch sizes**: Balance between file count and memory usage
2. **Use bincode for production**: Better performance and smaller files
3. **Validate dumps regularly**: Use the validation tools
4. **Monitor disk space**: Ensure adequate storage
5. **Test recovery procedures**: Verify dumps can be loaded successfully
6. **Use specific slot ranges**: For targeted reindexing operations

## Examples

### Complete Workflow Example

```bash
# 1. Start indexing with dumping enabled
photon --enable-block-dump --dump-dir /data/blocks --dump-format bincode --blocks-per-dump-file 1000

# 2. Check dump statistics
photon-dump-manager stats --dump-dir /data/blocks

# 3. Validate dumps
photon-dump-manager validate --dump-dir /data/blocks

# 4. Reindex from dumps (e.g., for testing)
photon --load-from-dumps /data/blocks --dump-start-slot 1000000 --dump-end-slot 1100000

# 5. List specific range
photon-dump-manager range --dump-dir /data/blocks --start-slot 1000000 --end-slot 1100000
```

This completes the block dumping and loading feature implementation for Photon!