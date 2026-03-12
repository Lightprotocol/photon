use crate::utils::*;
use photon_indexer::ingester::{
    index_block_batch,
    parser::{parse_transaction, TreeResolver},
    typedefs::block_info::{parse_ui_confirmed_blocked, BlockInfo},
};
use serial_test::serial;
use solana_pubkey::Pubkey;
use solana_transaction_status::UiConfirmedBlock;
use std::{fs, path::Path, str::FromStr};

type RelevantTx = (u64, String, Option<String>, Vec<u64>);

struct FixtureCase {
    fixture_name: &'static str,
    gap_tree: &'static str,
    gap_tx_signature: &'static str,
    gap_slot: u64,
}

const RAW_BLOCK_FIXTURE_4: FixtureCase = FixtureCase {
    fixture_name: "forester_ci_sequence_gap_dump_4",
    gap_tree: "bmt1LryLZUMmF7ZtqESaw7wifBXLfXHQYoE4GAmrahU",
    gap_tx_signature:
        "2p2ruZEnFwadYiPKNeAN8ypHvkmcDcGxoqHun9zNv8cNNA9d5hgn3vh5ouKFHGo24YP18u1paQxZWnPYo8geuZXd",
    gap_slot: 1641,
};

fn read_raw_blocks(fixture_name: &str) -> Vec<BlockInfo> {
    let base = format!("tests/data/blocks/{fixture_name}");
    let mut slots = fs::read_dir(&base)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if name == "summary.json" {
                return None;
            }
            name.parse::<u64>().ok()
        })
        .collect::<Vec<_>>();
    slots.sort_unstable();

    slots.into_iter()
        .map(|slot| {
            let path = format!("{base}/{slot}");
            let block = serde_json::from_str::<UiConfirmedBlock>(&fs::read_to_string(path).unwrap())
                .unwrap();
            parse_ui_confirmed_blocked(block, slot).unwrap()
        })
        .collect()
}

async fn replay_fixture_for_gap(fixture: &FixtureCase, db_backend: DatabaseBackend) {
    let fixture_dir = format!("tests/data/blocks/{}", fixture.fixture_name);
    assert!(
        Path::new(&fixture_dir).exists(),
        "expected raw block fixtures under {fixture_dir}"
    );

    let blocks = read_raw_blocks(fixture.fixture_name);
    assert!(
        blocks
            .iter()
            .find(|block| block.metadata.slot == fixture.gap_slot)
            .is_some_and(|block| {
                block.transactions.iter().any(|tx| {
                    tx.signature.to_string() == fixture.gap_tx_signature
                })
            }),
        "fixture should include gap tx {} at slot {}",
        fixture.gap_tx_signature,
        fixture.gap_slot
    );

    let setup = setup_with_options(
        fixture.fixture_name.to_string(),
        TestSetupOptions {
            network: Network::Localnet,
            db_backend,
        },
    )
    .await;
    reset_tables(setup.db_conn.as_ref()).await.unwrap();

    let mut observed_gap = None;
    let gap_tree = Pubkey::from_str(fixture.gap_tree).unwrap().to_bytes();
    let mut seen_gap_tree_sequences = Vec::<(u64, String, u64)>::new();
    let mut recent_relevant_txs = Vec::<RelevantTx>::new();

    for chunk in blocks.chunks(3) {
        let mut resolver = TreeResolver::new(setup.client.as_ref());
        for block in chunk {
            for transaction in &block.transactions {
                let state_update = parse_transaction(
                    setup.db_conn.as_ref(),
                    transaction,
                    block.metadata.slot,
                    &mut resolver,
                )
                .await
                .unwrap();
                let gap_tree_sequences = state_update
                    .batch_merkle_tree_events
                    .get(&gap_tree)
                    .map(|events| {
                        events
                            .iter()
                            .map(|event| {
                                seen_gap_tree_sequences.push((
                                    event.slot,
                                    event.signature.to_string(),
                                    event.sequence_number,
                                ));
                                event.sequence_number
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if transaction.error.is_some() || !gap_tree_sequences.is_empty() {
                    recent_relevant_txs.push((
                        block.metadata.slot,
                        transaction.signature.to_string(),
                        transaction.error.clone(),
                        gap_tree_sequences,
                    ));
                    if recent_relevant_txs.len() > 40 {
                        recent_relevant_txs.remove(0);
                    }
                }
            }
        }

        match index_block_batch(setup.db_conn.as_ref(), &chunk.to_vec(), setup.client.as_ref()).await
        {
            Ok(()) => {}
            Err(err) => {
                let err_string = err.to_string();
                if err_string.contains("Sequence gap detected") {
                    observed_gap = Some(err_string);
                    break;
                }
                panic!("unexpected replay error: {err}");
            }
        }
    }

    let gap = observed_gap.expect("expected raw block replay to reproduce the photon sequence gap");
    let recent_gap_tree_sequences = seen_gap_tree_sequences
        .iter()
        .rev()
        .take(24)
        .cloned()
        .collect::<Vec<_>>();
    let recent_relevant_txs = recent_relevant_txs
        .iter()
        .rev()
        .take(20)
        .cloned()
        .collect::<Vec<_>>();
    eprintln!(
        "recent parsed gap-tree sequences before failure: {:?}",
        recent_gap_tree_sequences.into_iter().rev().collect::<Vec<_>>()
    );
    eprintln!(
        "recent relevant txs before failure: {:?}",
        recent_relevant_txs.into_iter().rev().collect::<Vec<_>>()
    );
    eprintln!("observed replay gap: {gap}");
    assert!(
        gap.contains(fixture.gap_tree),
        "gap did not mention expected tree: {gap}"
    );
}

#[rstest]
#[tokio::test]
#[serial]
#[ignore = "diagnostic replay from a local forester raw-block CI fixture dump; enable when debugging photon sequence gaps"]
async fn reproduce_forester_ci_sequence_gap_from_raw_blocks_4(
    #[values(DatabaseBackend::Sqlite)] db_backend: DatabaseBackend,
) {
    replay_fixture_for_gap(&RAW_BLOCK_FIXTURE_4, db_backend).await;
}
