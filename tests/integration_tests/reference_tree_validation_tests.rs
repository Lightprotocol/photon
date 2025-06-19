use crate::utils::*;
use photon_indexer::common::typedefs::serializable_pubkey::SerializablePubkey;
use photon_indexer::ingester::index_block;
use photon_indexer::ingester::parser::parse_transaction;
use photon_indexer::ingester::persist::persist_state_update_inner;
use photon_indexer::ingester::typedefs::block_info::{BlockInfo, BlockMetadata};
use sea_orm::{ColumnTrait, DatabaseBackend, EntityTrait, QueryFilter, TransactionTrait};
use solana_pubkey::Pubkey;
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;
use std::str::FromStr;

fn read_transaction_from_file(
    test_name: &str,
    filename: &str,
) -> EncodedConfirmedTransactionWithStatusMeta {
    let file_path = format!("tests/data/transactions/{}/{}", test_name, filename);
    let file_content = std::fs::read_to_string(&file_path)
        .unwrap_or_else(|e| panic!("Failed to read transaction file {}: {}", file_path, e));
    serde_json::from_str(&file_content)
        .unwrap_or_else(|e| panic!("Failed to parse transaction JSON from {}: {}", file_path, e))
}

#[rstest]
async fn test_reference_tree_validation_on_each_insertion(
    #[values(DatabaseBackend::Postgres)] db_backend: DatabaseBackend,
) {
    let name = "txs_8bAVNbY2KtCsLZSGFRQ9s44p1sewzLz68q7DLFsBannh";
    let setup = setup_with_options(
        name.to_string(),
        TestSetupOptions {
            network: Network::Localnet,
            db_backend,
        },
    )
    .await;

    // Reset tables to ensure clean state
    reset_tables(setup.db_conn.as_ref()).await.unwrap();
    println!("Database reset");

    // Read transaction files sorted by slot
    let sort_by_slot = true;
    let signatures = read_file_names(name, sort_by_slot);
    println!(
        "Processing {} transactions for reference tree validation",
        signatures.len()
    );

    index_block(
        setup.db_conn.as_ref(),
        &BlockInfo {
            metadata: BlockMetadata {
                slot: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();

    for (i, signature) in signatures.iter().enumerate() {
        println!(
            "Processing transaction {}/{}: {}",
            i + 1,
            signatures.len(),
            signature
        );

        // Read the transaction directly from file
        let tx = read_transaction_from_file(name, signature);
        let state_update = parse_transaction(&tx.try_into().unwrap(), 0).unwrap();

        // // Check if any input accounts don't exist in the database (test data integrity issue)
        // let mut has_invalid_inputs = false;
        // let mut affected_trees = std::collections::HashSet::new();

        // for input_hash in &state_update.in_accounts {
        //     let exists = photon_indexer::dao::generated::accounts::Entity::find()
        //         .filter(
        //             photon_indexer::dao::generated::accounts::Column::Hash.eq(input_hash.to_vec()),
        //         )
        //         .one(setup.db_conn.as_ref())
        //         .await
        //         .unwrap();

        //     if exists.is_none() {
        //         println!(
        //             "  ⚠️  WARNING: Input account {:?} does not exist in database",
        //             input_hash
        //         );
        //         has_invalid_inputs = true;
        //     }
        // }

        // if has_invalid_inputs {
        //     // Collect trees from output accounts to show which trees are affected
        //     for out_acc in &state_update.out_accounts {
        //         affected_trees.insert(out_acc.account.tree.clone());
        //     }

        //     if !affected_trees.is_empty() {
        //         println!("      Affected trees in this transaction:");
        //         for tree in &affected_trees {
        //             let tree_pubkey =
        //                 SerializablePubkey::try_from(tree.to_bytes_vec()).unwrap_or_default();
        //             println!("        📊 Tree: {}", tree_pubkey);
        //         }
        //     }

        //     println!("      This indicates a test data integrity issue");
        //     println!(
        //         "⏭️  Skipped transaction {} due to invalid input accounts",
        //         signature
        //     );
        //     continue;
        // }

        // Process the transaction with validation enabled
        let txn = setup.db_conn.begin().await.unwrap();
        persist_state_update_with_validation(&txn, state_update)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        println!(
            "✓ Transaction {} processed and validated successfully",
            signature
        );
    }

    println!(
        "✓ All {} transactions processed with reference tree validation",
        signatures.len()
    );

    println!("Reference tree sizes after processing:");
    let tree_sizes = get_reference_tree_sizes();
    for (tree_bytes, size) in tree_sizes {
        let tree_pubkey = SerializablePubkey::try_from(tree_bytes).unwrap_or_default();
        println!("  Tree {}: {} leaves", tree_pubkey, size);
    }
}

async fn persist_state_update_with_validation(
    txn: &sea_orm::DatabaseTransaction,
    mut state_update: photon_indexer::ingester::parser::state_update::StateUpdate,
) -> Result<(), photon_indexer::ingester::error::IngesterError> {
    persist_state_update_inner(txn, &mut state_update, true).await
}

/// Helper function to get the sizes of all reference trees
fn get_reference_tree_sizes() -> Vec<(Vec<u8>, usize)> {
    use photon_indexer::ingester::persist::persisted_indexed_merkle_tree::REFERENCE_TREES;

    let reference_trees = REFERENCE_TREES.lock().unwrap();
    reference_trees
        .iter()
        .map(|(tree_bytes, tree)| (tree_bytes.clone(), tree.leaf_count()))
        .collect()
}

// #[rstest]
// async fn test_reference_tree_validation_batch_vs_individual(
//     #[values(DatabaseBackend::Sqlite)] db_backend: DatabaseBackend,
// ) {
//     let name = "tree_C7g8NqRsEDhi3v9AyVpCfL16YYdHPhrR74douckfrhqu";

//     // Test 1: Process all transactions individually with validation
//     let setup1 = setup_with_options(
//         format!("{}_individual", name),
//         TestSetupOptions {
//             network: Network::Localnet,
//             db_backend,
//         },
//     )
//     .await;
//     reset_tables(setup1.db_conn.as_ref()).await.unwrap();

//     let signatures = read_file_names(name, true);

//     // Index block
//     index_block(
//         setup1.db_conn.as_ref(),
//         &BlockInfo {
//             metadata: BlockMetadata {
//                 slot: 0,
//                 ..Default::default()
//             },
//             ..Default::default()
//         },
//     )
//     .await
//     .unwrap();

//     // Process each transaction individually
//     for signature in &signatures {
//         let tx = read_transaction_from_file(name, signature);
//         let state_update = parse_transaction(&tx.try_into().unwrap(), 0).unwrap();

//         let txn = setup1.db_conn.begin().await.unwrap();
//         persist_state_update_with_validation(&txn, state_update)
//             .await
//             .unwrap();
//         txn.commit().await.unwrap();
//     }

//     // Test 2: Process all transactions in batch with validation
//     let setup2 = setup_with_options(
//         format!("{}_batch", name),
//         TestSetupOptions {
//             network: Network::Localnet,
//             db_backend,
//         },
//     )
//     .await;
//     reset_tables(setup2.db_conn.as_ref()).await.unwrap();

//     // Index block
//     index_block(
//         setup2.db_conn.as_ref(),
//         &BlockInfo {
//             metadata: BlockMetadata {
//                 slot: 0,
//                 ..Default::default()
//             },
//             ..Default::default()
//         },
//     )
//     .await
//     .unwrap();

//     // Collect all state updates
//     let mut all_state_updates = Vec::new();
//     for signature in &signatures {
//         let tx = read_transaction_from_file(name, signature);
//         let state_update = parse_transaction(&tx.try_into().unwrap(), 0).unwrap();
//         all_state_updates.push(state_update);
//     }

//     // Merge and process all at once
//     let merged_state_update =
//         photon_indexer::ingester::parser::state_update::StateUpdate::merge_updates(
//             all_state_updates,
//         );
//     let txn = setup2.db_conn.begin().await.unwrap();
//     persist_state_update_with_validation(&txn, merged_state_update)
//         .await
//         .unwrap();
//     txn.commit().await.unwrap();

//     // Print reference tree sizes for both approaches
//     let tree_sizes1 = get_reference_tree_sizes();
//     let tree_sizes2 = get_reference_tree_sizes();

//     println!("✓ Both individual and batch processing completed with validation");
//     println!("Reference tree sizes after individual processing:");
//     for (tree_bytes, size) in tree_sizes1 {
//         let tree_pubkey = SerializablePubkey::try_from(tree_bytes).unwrap_or_default();
//         println!("  Tree {}: {} leaves", tree_pubkey, size);
//     }
//     println!("Reference tree sizes after batch processing:");
//     for (tree_bytes, size) in tree_sizes2 {
//         let tree_pubkey = SerializablePubkey::try_from(tree_bytes).unwrap_or_default();
//         println!("  Tree {}: {} leaves", tree_pubkey, size);
//     }
// }

// #[rstest]
// async fn test_reference_tree_validation_specific_tree(
//     #[values(DatabaseBackend::Sqlite)] db_backend: DatabaseBackend,
// ) {
//     let name = "tree_C7g8NqRsEDhi3v9AyVpCfL16YYdHPhrR74douckfrhqu";
//     let tree_pubkey = Pubkey::from_str("C7g8NqRsEDhi3v9AyVpCfL16YYdHPhrR74douckfrhqu").unwrap();

//     let setup = setup_with_options(
//         format!("{}_specific", name),
//         TestSetupOptions {
//             network: Network::Localnet,
//             db_backend,
//         },
//     )
//     .await;
//     reset_tables(setup.db_conn.as_ref()).await.unwrap();

//     let signatures = read_file_names(name, true);

//     // Index block
//     index_block(
//         setup.db_conn.as_ref(),
//         &BlockInfo {
//             metadata: BlockMetadata {
//                 slot: 0,
//                 ..Default::default()
//             },
//             ..Default::default()
//         },
//     )
//     .await
//     .unwrap();

//     println!(
//         "Testing reference tree validation for specific tree: {}",
//         tree_pubkey
//     );

//     // Process each transaction and verify it's updating the expected tree
//     for (i, signature) in signatures.iter().enumerate() {
//         let tx = read_transaction_from_file(name, signature);
//         let state_update = parse_transaction(&tx.try_into().unwrap(), 0).unwrap();

//         // Verify this transaction affects our target tree
//         let target_tree_serializable = SerializablePubkey::from(
//             solana_pubkey::Pubkey::new_from_array(tree_pubkey.to_bytes()),
//         );
//         let affects_target_tree = state_update
//             .out_accounts
//             .iter()
//             .any(|acc| acc.account.tree == target_tree_serializable);

//         if affects_target_tree {
//             println!("Transaction {} affects target tree", signature);
//         }

//         let txn = setup.db_conn.begin().await.unwrap();
//         persist_state_update_with_validation(&txn, state_update)
//             .await
//             .unwrap();
//         txn.commit().await.unwrap();

//         println!("✓ Transaction {}/{} validated", i + 1, signatures.len());
//     }

//     // Print reference tree size after all transactions
//     let tree_sizes = get_reference_tree_sizes();
//     println!(
//         "✓ All transactions for tree {} validated successfully",
//         tree_pubkey
//     );
//     println!("Reference tree sizes after processing:");
//     for (tree_bytes, size) in tree_sizes {
//         let tree_pubkey_display = SerializablePubkey::try_from(tree_bytes).unwrap_or_default();
//         println!("  Tree {}: {} leaves", tree_pubkey_display, size);
//     }
// }
