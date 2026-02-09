use std::collections::HashMap;
use std::sync::Arc;

use borsh::BorshDeserialize;
use clap::Parser;
use futures::StreamExt;
use log::{error, info};
use photon_indexer::common::{setup_logging, LoggingFormat};
use photon_indexer::ingester::parser::indexer_events::{MerkleTreeEvent, PublicTransactionEvent};
use photon_indexer::ingester::parser::tx_event_parser_v2::parse_public_transaction_event_v2;
use photon_indexer::ingester::parser::{get_compression_program_id, NOOP_PROGRAM_ID};
use photon_indexer::ingester::typedefs::block_info::TransactionInfo;
use photon_indexer::snapshot::{load_block_stream_from_directory_adapter, DirectoryAdapter};
use solana_pubkey::Pubkey;

/// Photon Snapshot Validator: validates that there are no sequence number gaps in snapshots
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Snapshot directory (local filesystem)
    #[arg(long)]
    snapshot_dir: Option<String>,

    /// R2 bucket name
    #[arg(long)]
    r2_bucket: Option<String>,

    /// R2 prefix
    #[arg(long, default_value = "")]
    r2_prefix: String,

    /// GCS bucket name
    #[arg(long)]
    gcs_bucket: Option<String>,

    /// GCS prefix
    #[arg(long, default_value = "")]
    gcs_prefix: String,

    /// Logging format
    #[arg(short, long, default_value_t = LoggingFormat::Standard)]
    logging_format: LoggingFormat,

    /// Show detailed output for each tree
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

/// Represents a sequence number occurrence
#[derive(Debug, Clone)]
struct SequenceOccurrence {
    seq: u64,
    slot: u64,
    signature: String,
    source: String,
}

/// Represents a gap in sequence numbers
#[derive(Debug)]
struct SequenceGap {
    tree: Pubkey,
    expected_seq: u64,
    found_seq: u64,
    slot: u64,
    signature: String,
}

/// Extract sequence numbers from a PublicTransactionEvent (V1)
fn extract_sequences_from_v1_event(
    event: &PublicTransactionEvent,
    slot: u64,
    signature: &str,
) -> Vec<(Pubkey, SequenceOccurrence)> {
    event
        .sequence_numbers
        .iter()
        .map(|seq| {
            (
                Pubkey::new_from_array(seq.pubkey.to_bytes()),
                SequenceOccurrence {
                    seq: seq.seq,
                    slot,
                    signature: signature.to_string(),
                    source: "PublicTransactionEvent".to_string(),
                },
            )
        })
        .collect()
}

/// Extract sequence numbers from MerkleTreeEvent
fn extract_sequences_from_merkle_event(
    event: &MerkleTreeEvent,
    slot: u64,
    signature: &str,
) -> Vec<(Pubkey, SequenceOccurrence)> {
    match event {
        MerkleTreeEvent::V1(changelog) => {
            // ChangelogEvent - seq is the base sequence, each path increments it
            let tree = Pubkey::new_from_array(changelog.id);
            changelog
                .paths
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    (
                        tree,
                        SequenceOccurrence {
                            seq: changelog.seq + i as u64,
                            slot,
                            signature: signature.to_string(),
                            source: "ChangelogEvent".to_string(),
                        },
                    )
                })
                .collect()
        }
        MerkleTreeEvent::V2(nullifier) => {
            // NullifierEvent - seq is base, each nullified leaf increments it
            let tree = Pubkey::new_from_array(nullifier.id);
            nullifier
                .nullified_leaves_indices
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    (
                        tree,
                        SequenceOccurrence {
                            seq: nullifier.seq + i as u64,
                            slot,
                            signature: signature.to_string(),
                            source: "NullifierEvent".to_string(),
                        },
                    )
                })
                .collect()
        }
        MerkleTreeEvent::V3(indexed) => {
            // IndexedMerkleTreeEvent - seq is base, each update has 2 leaves
            let tree = Pubkey::new_from_array(indexed.id);
            let mut result = Vec::new();
            let mut seq = indexed.seq;
            for _ in &indexed.updates {
                // Each update modifies 2 leaves (low and high element)
                result.push((
                    tree,
                    SequenceOccurrence {
                        seq,
                        slot,
                        signature: signature.to_string(),
                        source: "IndexedMerkleTreeEvent".to_string(),
                    },
                ));
                seq += 1;
                result.push((
                    tree,
                    SequenceOccurrence {
                        seq,
                        slot,
                        signature: signature.to_string(),
                        source: "IndexedMerkleTreeEvent".to_string(),
                    },
                ));
                seq += 1;
            }
            result
        }
        MerkleTreeEvent::BatchAppend(batch)
        | MerkleTreeEvent::BatchNullify(batch)
        | MerkleTreeEvent::BatchAddressAppend(batch) => {
            let tree = Pubkey::new_from_array(batch.merkle_tree_pubkey);
            let source = match event {
                MerkleTreeEvent::BatchAppend(_) => "BatchAppend",
                MerkleTreeEvent::BatchNullify(_) => "BatchNullify",
                MerkleTreeEvent::BatchAddressAppend(_) => "BatchAddressAppend",
                _ => unreachable!(),
            };
            vec![(
                tree,
                SequenceOccurrence {
                    seq: batch.sequence_number,
                    slot,
                    signature: signature.to_string(),
                    source: source.to_string(),
                },
            )]
        }
    }
}

/// Try to parse MerkleTreeEvent from NOOP instruction data
fn try_parse_merkle_tree_event(data: &[u8]) -> Option<MerkleTreeEvent> {
    MerkleTreeEvent::deserialize(&mut &data[..]).ok()
}

/// Try to parse PublicTransactionEvent from NOOP instruction data
fn try_parse_public_transaction_event(data: &[u8]) -> Option<PublicTransactionEvent> {
    PublicTransactionEvent::deserialize(&mut &data[..]).ok()
}

/// Extract all sequence numbers from a transaction
fn extract_sequences_from_transaction(
    tx: &TransactionInfo,
    slot: u64,
) -> Vec<(Pubkey, SequenceOccurrence)> {
    let mut sequences = Vec::new();
    let signature = tx.signature.to_string();

    if tx.error.is_some() {
        return sequences;
    }

    for instruction_group in &tx.instruction_groups {
        let mut ordered_instructions = Vec::new();
        ordered_instructions.push(&instruction_group.outer_instruction);
        ordered_instructions.extend(instruction_group.inner_instructions.iter());

        // Try V2 parsing first
        let program_ids: Vec<Pubkey> = ordered_instructions.iter().map(|i| i.program_id).collect();
        let instruction_data: Vec<Vec<u8>> = ordered_instructions
            .iter()
            .map(|i| i.data.clone())
            .collect();
        let accounts: Vec<Vec<Pubkey>> = ordered_instructions
            .iter()
            .map(|i| i.accounts.clone())
            .collect();

        if let Some(events) =
            parse_public_transaction_event_v2(&program_ids, &instruction_data, accounts)
        {
            for event in events {
                // Extract from V1 event embedded in V2
                sequences.extend(extract_sequences_from_v1_event(
                    &event.event,
                    slot,
                    &signature,
                ));

                // Extract from V2 input sequence numbers
                for seq in &event.input_sequence_numbers {
                    let tree = Pubkey::new_from_array(seq.tree_pubkey.to_bytes());
                    sequences.push((
                        tree,
                        SequenceOccurrence {
                            seq: seq.seq,
                            slot,
                            signature: signature.clone(),
                            source: "BatchPublicTransactionEvent(input)".to_string(),
                        },
                    ));
                }

                // Extract from V2 address sequence numbers
                for seq in &event.address_sequence_numbers {
                    let tree = Pubkey::new_from_array(seq.tree_pubkey.to_bytes());
                    sequences.push((
                        tree,
                        SequenceOccurrence {
                            seq: seq.seq,
                            slot,
                            signature: signature.clone(),
                            source: "BatchPublicTransactionEvent(address)".to_string(),
                        },
                    ));
                }
            }
        } else {
            // Fall back to V1 parsing
            for (index, instruction) in ordered_instructions.iter().enumerate() {
                // Check for NOOP instructions that might contain events
                if instruction.program_id == NOOP_PROGRAM_ID {
                    // Try to parse as MerkleTreeEvent
                    if let Some(event) = try_parse_merkle_tree_event(&instruction.data) {
                        sequences.extend(extract_sequences_from_merkle_event(
                            &event, slot, &signature,
                        ));
                    }
                    // Try to parse as PublicTransactionEvent
                    else if let Some(event) =
                        try_parse_public_transaction_event(&instruction.data)
                    {
                        sequences.extend(extract_sequences_from_v1_event(&event, slot, &signature));
                    }
                }

                // Also check pattern: compression instruction followed by NOOP
                if instruction.program_id == get_compression_program_id() {
                    if let Some(next_instruction) = ordered_instructions.get(index + 1) {
                        if next_instruction.program_id == NOOP_PROGRAM_ID {
                            if let Some(event) = try_parse_merkle_tree_event(&next_instruction.data)
                            {
                                sequences.extend(extract_sequences_from_merkle_event(
                                    &event, slot, &signature,
                                ));
                            } else if let Some(event) =
                                try_parse_public_transaction_event(&next_instruction.data)
                            {
                                sequences.extend(extract_sequences_from_v1_event(
                                    &event, slot, &signature,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    sequences
}

/// Validate sequences for gaps
fn validate_sequences(
    sequences_by_tree: HashMap<Pubkey, Vec<SequenceOccurrence>>,
    verbose: bool,
) -> Vec<SequenceGap> {
    let mut gaps = Vec::new();

    for (tree, mut occurrences) in sequences_by_tree {
        // Sort by sequence number
        occurrences.sort_by_key(|o| o.seq);

        if occurrences.is_empty() {
            continue;
        }

        if verbose {
            // Count occurrences by source type
            let mut sources: HashMap<&str, usize> = HashMap::new();
            for o in &occurrences {
                *sources.entry(o.source.as_str()).or_default() += 1;
            }
            let sources_str: Vec<String> = sources
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .collect();

            info!(
                "Tree {}: {} sequence occurrences, range {} - {}, sources: [{}]",
                tree,
                occurrences.len(),
                occurrences.first().map(|o| o.seq).unwrap_or(0),
                occurrences.last().map(|o| o.seq).unwrap_or(0),
                sources_str.join(", ")
            );
        }

        // Check for gaps
        let mut expected_seq = occurrences[0].seq;
        for occurrence in &occurrences {
            if occurrence.seq > expected_seq {
                gaps.push(SequenceGap {
                    tree,
                    expected_seq,
                    found_seq: occurrence.seq,
                    slot: occurrence.slot,
                    signature: occurrence.signature.clone(),
                });
                // Jump to the found sequence
                expected_seq = occurrence.seq;
            }
            // Allow duplicates (same sequence can appear multiple times in batch operations)
            if occurrence.seq >= expected_seq {
                expected_seq = occurrence.seq + 1;
            }
        }
    }

    gaps
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    setup_logging(args.logging_format);

    let directory_adapter = match (
        args.snapshot_dir.clone(),
        args.r2_bucket.clone(),
        args.gcs_bucket.clone(),
    ) {
        (Some(snapshot_dir), None, None) => {
            Arc::new(DirectoryAdapter::from_local_directory(snapshot_dir))
        }
        (None, Some(r2_bucket), None) => Arc::new(
            DirectoryAdapter::from_r2_bucket_and_prefix_and_env(r2_bucket, args.r2_prefix.clone())
                .await,
        ),
        #[cfg(feature = "gcs")]
        (None, None, Some(gcs_bucket)) => Arc::new(
            DirectoryAdapter::from_gcs_bucket_and_prefix_and_env(
                gcs_bucket,
                args.gcs_prefix.clone(),
            )
            .await,
        ),
        _ => {
            error!("Exactly one of snapshot_dir, r2_bucket, or gcs_bucket must be provided");
            return Err(anyhow::anyhow!(
                "Exactly one of snapshot_dir, r2_bucket, or gcs_bucket must be provided"
            ));
        }
    };

    info!("Loading snapshots...");

    let block_stream = load_block_stream_from_directory_adapter(directory_adapter).await;
    futures::pin_mut!(block_stream);

    let mut sequences_by_tree: HashMap<Pubkey, Vec<SequenceOccurrence>> = HashMap::new();
    let mut total_blocks = 0u64;
    let mut total_transactions = 0u64;
    let mut total_sequences = 0u64;
    let mut first_slot: Option<u64> = None;
    let mut last_slot: Option<u64> = None;

    while let Some(blocks) = block_stream.next().await {
        for block in blocks {
            let slot = block.metadata.slot;
            if first_slot.is_none() {
                first_slot = Some(slot);
            }
            last_slot = Some(slot);
            total_blocks += 1;

            for tx in &block.transactions {
                total_transactions += 1;
                let sequences = extract_sequences_from_transaction(tx, slot);
                total_sequences += sequences.len() as u64;

                for (tree, occurrence) in sequences {
                    sequences_by_tree.entry(tree).or_default().push(occurrence);
                }
            }

            if total_blocks % 10000 == 0 {
                info!(
                    "Processed {} blocks, {} transactions, {} sequences...",
                    total_blocks, total_transactions, total_sequences
                );
            }
        }
    }

    info!("Finished loading snapshot data.");
    info!(
        "Slot range: {} - {}",
        first_slot.unwrap_or(0),
        last_slot.unwrap_or(0)
    );
    info!("Total blocks: {}", total_blocks);
    info!("Total transactions: {}", total_transactions);
    info!("Total sequence occurrences: {}", total_sequences);
    info!("Unique trees: {}", sequences_by_tree.len());

    info!("Validating sequences for gaps...");

    let gaps = validate_sequences(sequences_by_tree, args.verbose);

    if gaps.is_empty() {
        info!("✓ No sequence gaps detected!");
    } else {
        error!("✗ Found {} sequence gaps:", gaps.len());
        for gap in &gaps {
            error!(
                "  Tree {}: expected seq {}, found seq {} (gap of {}) at slot {}, tx {}",
                gap.tree,
                gap.expected_seq,
                gap.found_seq,
                gap.found_seq - gap.expected_seq,
                gap.slot,
                gap.signature
            );
        }
        return Err(anyhow::anyhow!("Sequence gaps detected"));
    }

    Ok(())
}
