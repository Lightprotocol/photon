use std::collections::HashMap;
use std::sync::Arc;

use borsh::BorshDeserialize;
use futures::StreamExt;
use log::info;
use solana_pubkey::Pubkey;

use photon_indexer::ingester::parser::indexer_events::{MerkleTreeEvent, PublicTransactionEvent};
use photon_indexer::ingester::parser::tx_event_parser_v2::parse_public_transaction_event_v2;
use photon_indexer::ingester::parser::{get_compression_program_id, NOOP_PROGRAM_ID};
use photon_indexer::ingester::typedefs::block_info::TransactionInfo;
use photon_indexer::snapshot::{load_block_stream_from_directory_adapter, DirectoryAdapter};

/// Represents a sequence number occurrence with slot information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SequenceOccurrence {
    pub seq: u64,
    pub slot: u64,
    pub signature: String,
    pub source: String,
}

/// Enhanced gap information with slot range for repair
#[derive(Debug, Clone)]
pub struct EnhancedSequenceGap {
    pub tree: Pubkey,
    pub expected_seq: u64,
    pub found_seq: u64,
    pub gap_slot: u64,
    pub gap_signature: String,
    pub prev_seq_slot: u64,
}

/// Result of gap analysis
#[allow(dead_code)]
pub struct GapAnalysisResult {
    pub gaps: Vec<EnhancedSequenceGap>,
    pub first_slot: u64,
    pub last_slot: u64,
    pub total_blocks: u64,
    pub total_transactions: u64,
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
            let tree = Pubkey::new_from_array(indexed.id);
            let mut result = Vec::new();
            let mut seq = indexed.seq;
            for _ in &indexed.updates {
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

fn try_parse_merkle_tree_event(data: &[u8]) -> Option<MerkleTreeEvent> {
    MerkleTreeEvent::deserialize(&mut &data[..]).ok()
}

fn try_parse_public_transaction_event(data: &[u8]) -> Option<PublicTransactionEvent> {
    PublicTransactionEvent::deserialize(&mut &data[..]).ok()
}

/// Extract all sequence numbers from a transaction
pub fn extract_sequences_from_transaction(
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

        let program_ids: Vec<Pubkey> = ordered_instructions
            .iter()
            .map(|i| i.program_id)
            .collect();
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
                sequences.extend(extract_sequences_from_v1_event(
                    &event.event,
                    slot,
                    &signature,
                ));

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
            for (index, instruction) in ordered_instructions.iter().enumerate() {
                if instruction.program_id == NOOP_PROGRAM_ID {
                    if let Some(event) = try_parse_merkle_tree_event(&instruction.data) {
                        sequences
                            .extend(extract_sequences_from_merkle_event(&event, slot, &signature));
                    } else if let Some(event) =
                        try_parse_public_transaction_event(&instruction.data)
                    {
                        sequences.extend(extract_sequences_from_v1_event(&event, slot, &signature));
                    }
                }

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

/// Analyze sequences and detect gaps with slot tracking
fn analyze_sequences_with_slot_tracking(
    sequences_by_tree: HashMap<Pubkey, Vec<SequenceOccurrence>>,
    snapshot_start_slot: u64,
) -> Vec<EnhancedSequenceGap> {
    let mut gaps = Vec::new();

    for (tree, mut occurrences) in sequences_by_tree {
        occurrences.sort_by_key(|o| o.seq);

        if occurrences.is_empty() {
            continue;
        }

        // Build a map of sequence -> slot for looking up previous sequence slots
        let seq_to_slot: HashMap<u64, u64> = occurrences
            .iter()
            .map(|o| (o.seq, o.slot))
            .collect();

        let mut expected_seq = occurrences[0].seq;
        for occurrence in &occurrences {
            if occurrence.seq > expected_seq {
                // Gap found! Determine the slot of the previous sequence
                let prev_seq = expected_seq.saturating_sub(1);
                let prev_seq_slot = seq_to_slot
                    .get(&prev_seq)
                    .copied()
                    .unwrap_or(snapshot_start_slot);

                gaps.push(EnhancedSequenceGap {
                    tree,
                    expected_seq,
                    found_seq: occurrence.seq,
                    gap_slot: occurrence.slot,
                    gap_signature: occurrence.signature.clone(),
                    prev_seq_slot,
                });
                expected_seq = occurrence.seq;
            }
            if occurrence.seq >= expected_seq {
                expected_seq = occurrence.seq + 1;
            }
        }
    }

    gaps
}

/// Analyze snapshot for gaps and return enhanced gap information
pub async fn analyze_snapshot_gaps(
    directory_adapter: Arc<DirectoryAdapter>,
) -> anyhow::Result<GapAnalysisResult> {
    info!("Loading snapshots for gap analysis...");

    let block_stream = load_block_stream_from_directory_adapter(directory_adapter).await;
    futures::pin_mut!(block_stream);

    let mut sequences_by_tree: HashMap<Pubkey, Vec<SequenceOccurrence>> = HashMap::new();
    let mut total_blocks = 0u64;
    let mut total_transactions = 0u64;
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

                for (tree, occurrence) in sequences {
                    sequences_by_tree.entry(tree).or_default().push(occurrence);
                }
            }

            if total_blocks % 10000 == 0 {
                info!("Analyzed {} blocks...", total_blocks);
            }
        }
    }

    let first_slot = first_slot.unwrap_or(0);
    let last_slot = last_slot.unwrap_or(0);

    info!("Finished loading. Analyzing for gaps...");
    info!("Slot range: {} - {}", first_slot, last_slot);
    info!("Total blocks: {}", total_blocks);
    info!("Total transactions: {}", total_transactions);
    info!("Unique trees: {}", sequences_by_tree.len());

    let gaps = analyze_sequences_with_slot_tracking(sequences_by_tree, first_slot);

    Ok(GapAnalysisResult {
        gaps,
        first_slot,
        last_slot,
        total_blocks,
        total_transactions,
    })
}

/// Compute the set of slots that need to be refetched based on gaps
pub fn compute_slots_to_fetch(gaps: &[EnhancedSequenceGap]) -> Vec<u64> {
    let mut slots: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for gap in gaps {
        // Add all slots in the range [prev_seq_slot + 1, gap_slot - 1]
        // These are the slots that might contain the missing sequences
        let start = gap.prev_seq_slot.saturating_add(1);
        let end = gap.gap_slot.saturating_sub(1);

        if start <= end {
            for slot in start..=end {
                slots.insert(slot);
            }
        }
    }

    let mut sorted_slots: Vec<u64> = slots.into_iter().collect();
    sorted_slots.sort();
    sorted_slots
}
