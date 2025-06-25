use crate::utils::*;
use function_name::named;
use light_compressed_account::indexer_event::event::BatchNullifyContext;
use light_compressed_account::TreeType;
use light_hasher::Poseidon;
use light_merkle_tree_reference::MerkleTree;
use photon_indexer::common::typedefs::account::AccountData;
use photon_indexer::common::typedefs::account::{Account, AccountContext, AccountWithContext};
use photon_indexer::common::typedefs::bs64_string::Base64String;
use photon_indexer::common::typedefs::hash::Hash;
use photon_indexer::common::typedefs::serializable_pubkey::SerializablePubkey;
use photon_indexer::common::typedefs::unsigned_integer::UnsignedInteger;
use photon_indexer::ingester::parser::indexer_events::RawIndexedElement;
use photon_indexer::ingester::parser::state_update::{
    AccountTransaction, AddressQueueUpdate, IndexedTreeLeafUpdate, LeafNullification, StateUpdate,
    Transaction,
};
use photon_indexer::ingester::parser::tree_info::TreeInfo;
use photon_indexer::ingester::persist::persist_state_update;
use rand::{
    rngs::{StdRng, ThreadRng},
    Rng, RngCore, SeedableRng,
};
use sea_orm::{
    prelude::Decimal, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    TransactionTrait,
};
use serial_test::serial;
use solana_sdk::signature::Signature;
use std::env;

// Use the specific trees from QUEUE_TREE_MAPPING
const V1_TEST_TREE_PUBKEY_STR: &str = "smt1NamzXdq4AMqS2fS2F1i5KTYPZRhoHgWx38d8WsT";
const V2_TEST_TREE_PUBKEY_STR: &str = "HLKs5NJ8FXkJg8BrzJt56adFYYuwg5etzDtBbQYTsixu";
const V2_TEST_QUEUE_PUBKEY_STR: &str = "6L7SzhYB3anwEQ9cphpJ1U7Scwj57bx2xueReg7R9cKU";

/// Configuration for generating random collections
#[derive(Debug, Clone)]
pub struct CollectionConfig {
    pub min_entries: usize,
    pub max_entries: usize,
    pub probability: f64,
}

impl CollectionConfig {
    pub fn new(min_entries: usize, max_entries: usize, probability: f64) -> Self {
        Self {
            min_entries,
            max_entries,
            probability,
        }
    }
}

/// Metadata about what was generated in a StateUpdate
#[derive(Debug, Clone)]
pub struct StateUpdateMetadata {
    pub in_accounts_v1_count: usize,
    pub in_accounts_v2_count: usize,
    pub out_accounts_v1_count: usize,
    pub out_accounts_v2_count: usize,
    pub account_transactions_count: usize,
    pub transactions_count: usize,
    pub leaf_nullifications_count: usize,
    pub indexed_merkle_tree_updates_count: usize,
    pub batch_nullify_context_count: usize,
    pub batch_new_addresses_count: usize,
}

/// Configuration for generating random StateUpdate data
#[derive(Debug, Clone)]
pub struct StateUpdateConfig {
    // Collection configurations for StateUpdate fields
    pub in_accounts_v1: CollectionConfig,
    pub in_accounts_v2: CollectionConfig,
    pub out_accounts_v1: CollectionConfig,
    pub out_accounts_v2: CollectionConfig,
    pub account_transactions: CollectionConfig,
    pub transactions: CollectionConfig,
    pub leaf_nullifications: CollectionConfig,
    pub indexed_merkle_tree_updates: CollectionConfig,
    pub batch_nullify_context: CollectionConfig,
    pub batch_new_addresses: CollectionConfig,

    // Value ranges for various types
    pub lamports_min: u64,
    pub lamports_max: u64,
    pub discriminator_min: u64,
    pub discriminator_max: u64,
    pub data_size_min: usize,
    pub data_size_max: usize,
}

impl Default for StateUpdateConfig {
    fn default() -> Self {
        Self {
            in_accounts_v1: CollectionConfig::new(0, 3, 0.3),
            in_accounts_v2: CollectionConfig::new(0, 3, 0.3),
            out_accounts_v1: CollectionConfig::new(0, 5, 1.0),
            out_accounts_v2: CollectionConfig::new(0, 5, 1.0),
            account_transactions: CollectionConfig::new(0, 3, 0.0),
            transactions: CollectionConfig::new(0, 2, 0.0),
            leaf_nullifications: CollectionConfig::new(0, 3, 0.0),
            indexed_merkle_tree_updates: CollectionConfig::new(0, 3, 0.0),
            batch_nullify_context: CollectionConfig::new(0, 2, 0.0),
            batch_new_addresses: CollectionConfig::new(0, 3, 0.0),

            lamports_min: 1000,
            lamports_max: 1_000_000,
            discriminator_min: 1000,
            discriminator_max: 1_000_000,
            data_size_min: 0,
            data_size_max: 100,
        }
    }
}

/// Generate a random StateUpdate following the light-protocol pattern
fn get_rnd_state_update(
    rng: &mut StdRng,
    config: &StateUpdateConfig,
    slot: u64,
    base_seq_v1: u64,
    base_leaf_index_v1: u64,
    base_leaf_index_v2: u64,
    _base_nullifier_queue_index: u64,
    v1_available_accounts_for_spending: &mut Vec<Hash>,
    v2_available_accounts_for_spending: &mut Vec<Hash>,
) -> (StateUpdate, StateUpdateMetadata) {
    let mut state_update = StateUpdate::default();
    let mut metadata = StateUpdateMetadata {
        in_accounts_v1_count: 0,
        in_accounts_v2_count: 0,
        out_accounts_v1_count: 0,
        out_accounts_v2_count: 0,
        account_transactions_count: 0,
        transactions_count: 0,
        leaf_nullifications_count: 0,
        indexed_merkle_tree_updates_count: 0,
        batch_nullify_context_count: 0,
        batch_new_addresses_count: 0,
    };

    // Generate in_accounts (HashSet<Hash>) - v1 accounts that will be spent
    if !v1_available_accounts_for_spending.is_empty()
        && rng.gen_bool(config.in_accounts_v1.probability)
    {
        let max_to_spend = config
            .in_accounts_v1
            .max_entries
            .min(v1_available_accounts_for_spending.len());
        let count = rng.gen_range(config.in_accounts_v1.min_entries..=max_to_spend);

        for _i in 0..count {
            if !v1_available_accounts_for_spending.is_empty() {
                let index = rng.gen_range(0..v1_available_accounts_for_spending.len());
                let account_hash = v1_available_accounts_for_spending.remove(index);
                state_update.in_accounts.insert(account_hash);
                metadata.in_accounts_v1_count += 1;
            }
        }
    }

    // Generate in_accounts (HashSet<Hash>) - v2 accounts that will be spent
    if !v2_available_accounts_for_spending.is_empty()
        && rng.gen_bool(config.in_accounts_v2.probability)
    {
        let max_to_spend = config
            .in_accounts_v2
            .max_entries
            .min(v2_available_accounts_for_spending.len());
        let count = rng.gen_range(config.in_accounts_v2.min_entries..=max_to_spend);

        for _i in 0..count {
            if !v2_available_accounts_for_spending.is_empty() {
                let index = rng.gen_range(0..v2_available_accounts_for_spending.len());
                let account_hash = v2_available_accounts_for_spending.remove(index);
                state_update.in_accounts.insert(account_hash);
                metadata.in_accounts_v2_count += 1;
            }
        }
    }

    // Generate out_accounts (Vec<AccountWithContext>)
    if rng.gen_bool(config.out_accounts_v1.probability) {
        // Get tree info from QUEUE_TREE_MAPPING
        let tree_info = TreeInfo::get(V1_TEST_TREE_PUBKEY_STR)
            .expect("Test tree should exist in QUEUE_TREE_MAPPING");
        let test_tree_pubkey = tree_info.tree;

        let count =
            rng.gen_range(config.out_accounts_v1.min_entries..=config.out_accounts_v1.max_entries);
        metadata.out_accounts_v1_count = count as usize;
        for i in 0..count {
            let account = AccountWithContext {
                account: Account {
                    hash: Hash::new_unique(),
                    address: if rng.gen_bool(0.7) {
                        Some(SerializablePubkey::new_unique())
                    } else {
                        None
                    },
                    data: if rng.gen_bool(0.6) {
                        let data_size = rng.gen_range(config.data_size_min..=config.data_size_max);
                        Some(AccountData {
                            discriminator: UnsignedInteger(
                                rng.gen_range(config.discriminator_min..=config.discriminator_max),
                            ),
                            data: Base64String((0..data_size).map(|_| rng.gen()).collect()),
                            data_hash: Hash::new_unique(),
                        })
                    } else {
                        None
                    },
                    owner: SerializablePubkey::new_unique(),
                    lamports: UnsignedInteger(
                        rng.gen_range(config.lamports_min as i64..=config.lamports_max as i64)
                            as u64,
                    ),
                    tree: SerializablePubkey::from(test_tree_pubkey),
                    leaf_index: UnsignedInteger(base_leaf_index_v1 + i as u64),
                    seq: Some(UnsignedInteger(base_seq_v1 + i as u64)),
                    slot_created: UnsignedInteger(slot),
                },
                context: AccountContext {
                    tree_type: TreeType::StateV1 as u16,
                    queue: tree_info.queue.into(),
                    tx_hash: None,          // V1 accounts never have tx_hash
                    in_output_queue: false, // V1 accounts don't use output queues
                    ..Default::default()
                },
            };
            state_update.out_accounts.push(account);
        }
    }

    // Generate out_accounts (Vec<AccountWithContext>)
    if rng.gen_bool(config.out_accounts_v2.probability) {
        // Get tree info from QUEUE_TREE_MAPPING
        let tree_info = TreeInfo::get(V2_TEST_TREE_PUBKEY_STR)
            .expect("Test tree should exist in QUEUE_TREE_MAPPING");
        let test_tree_pubkey = tree_info.tree;

        let count =
            rng.gen_range(config.out_accounts_v2.min_entries..=config.out_accounts_v2.max_entries);
        metadata.out_accounts_v2_count = count as usize;
        for i in 0..count {
            let account = AccountWithContext {
                account: Account {
                    hash: Hash::new_unique(),
                    address: if rng.gen_bool(0.7) {
                        Some(SerializablePubkey::new_unique())
                    } else {
                        None
                    },
                    data: if rng.gen_bool(0.6) {
                        let data_size = rng.gen_range(config.data_size_min..=config.data_size_max);
                        Some(AccountData {
                            discriminator: UnsignedInteger(
                                rng.gen_range(config.discriminator_min..=config.discriminator_max),
                            ),
                            data: Base64String((0..data_size).map(|_| rng.gen()).collect()),
                            data_hash: Hash::new_unique(),
                        })
                    } else {
                        None
                    },
                    owner: SerializablePubkey::new_unique(),
                    lamports: UnsignedInteger(
                        rng.gen_range(config.lamports_min as i64..=config.lamports_max as i64)
                            as u64,
                    ),
                    tree: SerializablePubkey::from(test_tree_pubkey),
                    leaf_index: UnsignedInteger(base_leaf_index_v2 + i as u64),
                    seq: None, // V2 accounts in output queue don't have seq initially
                    slot_created: UnsignedInteger(slot),
                },
                context: AccountContext {
                    tree_type: TreeType::StateV2 as u16,
                    queue: tree_info.queue.into(),
                    in_output_queue: true, // V2 accounts use output queues
                    tx_hash: if rng.gen_bool(0.5) {
                        Some(Hash::from(rng.gen::<[u8; 32]>()))
                    } else {
                        None
                    },
                    ..Default::default()
                },
            };
            state_update.out_accounts.push(account);
        }
    }

    // Kept until we introduce v1 and v2 differentiation for nullification
    // Get tree info from QUEUE_TREE_MAPPING
    let tree_info = TreeInfo::get(V1_TEST_TREE_PUBKEY_STR)
        .expect("Test tree should exist in QUEUE_TREE_MAPPING");
    let test_tree_pubkey = tree_info.tree;

    // Generate account_transactions (HashSet<AccountTransaction>)
    if rng.gen_bool(config.account_transactions.probability) {
        let count = rng.gen_range(
            config.account_transactions.min_entries..=config.account_transactions.max_entries,
        );
        for _i in 0..count {
            let mut sig_bytes = [0u8; 64];
            rng.fill(&mut sig_bytes);
            state_update
                .account_transactions
                .insert(AccountTransaction {
                    hash: Hash::new_unique(),
                    signature: Signature::from(sig_bytes),
                });
        }
    }

    // Generate transactions (HashSet<Transaction>)
    if rng.gen_bool(config.transactions.probability) {
        let count =
            rng.gen_range(config.transactions.min_entries..=config.transactions.max_entries);
        for _i in 0..count {
            let mut sig_bytes = [0u8; 64];
            rng.fill(&mut sig_bytes);
            state_update.transactions.insert(Transaction {
                signature: Signature::from(sig_bytes),
                slot,
                uses_compression: rng.gen(),
                error: if rng.gen_bool(0.1) {
                    Some("Random error".to_string())
                } else {
                    None
                },
            });
        }
    }

    // Generate leaf_nullifications (HashSet<LeafNullification>)
    if rng.gen_bool(config.leaf_nullifications.probability) {
        let count = rng.gen_range(
            config.leaf_nullifications.min_entries..=config.leaf_nullifications.max_entries,
        );
        for i in 0..count {
            let mut sig_bytes = [0u8; 64];
            rng.fill(&mut sig_bytes);
            state_update.leaf_nullifications.insert(LeafNullification {
                tree: test_tree_pubkey,
                leaf_index: base_leaf_index_v1 + i as u64,
                seq: base_seq_v1 + i as u64,
                signature: Signature::from(sig_bytes),
            });
        }
    }

    // Generate indexed_merkle_tree_updates (HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>)
    if rng.gen_bool(config.indexed_merkle_tree_updates.probability) {
        let count = rng.gen_range(
            config.indexed_merkle_tree_updates.min_entries
                ..=config.indexed_merkle_tree_updates.max_entries,
        );
        for i in 0..count {
            let tree = test_tree_pubkey;
            let index = base_leaf_index_v1 + i as u64;
            let update = IndexedTreeLeafUpdate {
                tree,
                leaf: RawIndexedElement {
                    value: rng.gen::<[u8; 32]>(),
                    next_index: rng.gen::<u32>() as usize,
                    next_value: rng.gen::<[u8; 32]>(),
                    index: (base_leaf_index_v1 + i as u64) as usize,
                },
                hash: rng.gen::<[u8; 32]>(),
                seq: base_seq_v1 + i as u64,
            };
            state_update
                .indexed_merkle_tree_updates
                .insert((tree, index), update);
        }
    }

    // Generate batch_nullify_context (Vec<BatchNullifyContext>)
    if rng.gen_bool(config.batch_nullify_context.probability) {
        let count = rng.gen_range(
            config.batch_nullify_context.min_entries..=config.batch_nullify_context.max_entries,
        );
        for i in 0..count {
            state_update
                .batch_nullify_context
                .push(BatchNullifyContext {
                    tx_hash: rng.gen::<[u8; 32]>(),
                    account_hash: rng.gen::<[u8; 32]>(),
                    nullifier: rng.gen::<[u8; 32]>(),
                    nullifier_queue_index: i as u64,
                });
        }
    }

    // Generate batch_new_addresses (Vec<AddressQueueUpdate>)
    if rng.gen_bool(config.batch_new_addresses.probability) {
        let count = rng.gen_range(
            config.batch_new_addresses.min_entries..=config.batch_new_addresses.max_entries,
        );
        for i in 0..count {
            state_update.batch_new_addresses.push(AddressQueueUpdate {
                tree: SerializablePubkey::from(test_tree_pubkey),
                address: rng.gen::<[u8; 32]>(),
                queue_index: i as u64,
            });
        }
    }

    // Note: batch_merkle_tree_events is left as default since it's complex and rarely used

    (state_update, metadata)
}

/// Helper function to persist a state update and commit the transaction
async fn persist_state_update_and_commit(
    db_conn: &DatabaseConnection,
    state_update: StateUpdate,
) -> Result<(), Box<dyn std::error::Error>> {
    let txn = db_conn.begin().await?;
    persist_state_update(&txn, state_update).await?;
    txn.commit().await?;
    Ok(())
}

/// Helper function to fetch pre-existing account models for input accounts
async fn fetch_pre_existing_input_models(
    db_conn: &DatabaseConnection,
    state_update: &StateUpdate,
) -> Result<Vec<photon_indexer::dao::generated::accounts::Model>, Box<dyn std::error::Error>> {
    use photon_indexer::dao::generated::accounts;
    use sea_orm::ColumnTrait;

    if state_update.in_accounts.is_empty() {
        return Ok(Vec::new());
    }

    let input_hashes: Vec<Vec<u8>> = state_update
        .in_accounts
        .iter()
        .map(|hash| hash.0.to_vec())
        .collect();

    let models = accounts::Entity::find()
        .filter(accounts::Column::Hash.is_in(input_hashes))
        .all(db_conn)
        .await?;

    Ok(models)
}

/// Helper function to update test state after processing a state update
fn update_test_state_after_iteration(
    state_update: &StateUpdate,
    metadata: &StateUpdateMetadata,
    v1_available_accounts_for_spending: &mut Vec<Hash>,
    v2_available_accounts_for_spending: &mut Vec<Hash>,
    base_seq_v1: &mut u64,
    base_leaf_index_v1: &mut u64,
    base_leaf_index_v2: &mut u64,
    base_nullifier_queue_index: &mut u64,
) {
    // Collect new v1 output accounts for future spending
    let new_v1_accounts: Vec<Hash> = state_update
        .out_accounts
        .iter()
        .filter(|acc| acc.context.tree_type == TreeType::StateV1 as u16)
        .map(|acc| acc.account.hash.clone())
        .collect();
    v1_available_accounts_for_spending.extend(new_v1_accounts.iter().cloned());

    // Collect new v2 output accounts for future spending
    let new_v2_accounts: Vec<Hash> = state_update
        .out_accounts
        .iter()
        .filter(|acc| acc.context.tree_type == TreeType::StateV2 as u16)
        .map(|acc| acc.account.hash.clone())
        .collect();
    v2_available_accounts_for_spending.extend(new_v2_accounts.iter().cloned());

    // Update indices using metadata for precise counts
    let v1_output_count = metadata.out_accounts_v1_count as u64;
    let v2_output_count = metadata.out_accounts_v2_count as u64;
    let _v1_input_count = metadata.in_accounts_v1_count as u64;
    let v2_input_count = metadata.in_accounts_v2_count as u64;

    *base_seq_v1 += v1_output_count;
    *base_leaf_index_v1 += v1_output_count;
    *base_leaf_index_v2 += v2_output_count;
    *base_nullifier_queue_index += v2_input_count; // Only v2 input accounts get nullifier queue positions

    println!(
        "Available accounts for spending: v1={}, v2={}",
        v1_available_accounts_for_spending.len(),
        v2_available_accounts_for_spending.len()
    );
}

/// Assert that all output accounts from the state update were inserted correctly into the database
async fn assert_output_accounts_persisted(
    db_conn: &DatabaseConnection,
    metadata: &StateUpdateMetadata,
    state_update: &StateUpdate,
) -> Result<(), Box<dyn std::error::Error>> {
    use photon_indexer::dao::generated::accounts;
    use sea_orm::ColumnTrait;

    // Validate metadata matches actual state update
    let expected_total_out_accounts =
        metadata.out_accounts_v1_count + metadata.out_accounts_v2_count;
    assert_eq!(
        state_update.out_accounts.len(),
        expected_total_out_accounts,
        "Metadata out_accounts count ({}) doesn't match actual out_accounts ({})",
        expected_total_out_accounts,
        state_update.out_accounts.len()
    );

    if state_update.out_accounts.is_empty() {
        // If no accounts expected, verify table is empty
        // let account_count = accounts::Entity::find().count(db_conn).await?;
        // assert_eq!(
        //     account_count, 0,
        //     "Expected no accounts in database, but found {}",
        //     account_count
        // );
        return Ok(());
    }

    // Validate v1/v2 split matches metadata
    let actual_v1_count = state_update
        .out_accounts
        .iter()
        .filter(|acc| acc.context.tree_type == 1) // TreeType::StateV1
        .count();
    let actual_v2_count = state_update
        .out_accounts
        .iter()
        .filter(|acc| acc.context.tree_type == 3) // TreeType::StateV2
        .count();

    assert_eq!(
        actual_v1_count, metadata.out_accounts_v1_count,
        "Metadata v1 out_accounts count ({}) doesn't match actual v1 count ({})",
        metadata.out_accounts_v1_count, actual_v1_count
    );

    assert_eq!(
        actual_v2_count, metadata.out_accounts_v2_count,
        "Metadata v2 out_accounts count ({}) doesn't match actual v2 count ({})",
        metadata.out_accounts_v2_count, actual_v2_count
    );

    // Create expected models from state update
    let expected_models: Vec<accounts::Model> = state_update
        .out_accounts
        .iter()
        .map(|account_with_context| {
            let account = &account_with_context.account;
            let context = &account_with_context.context;
            accounts::Model {
                hash: account.hash.0.to_vec(),
                data: account.data.as_ref().map(|data| data.data.0.clone()),
                data_hash: account.data.as_ref().map(|data| data.data_hash.0.to_vec()),
                address: account
                    .address
                    .as_ref()
                    .map(|addr| addr.0.to_bytes().to_vec()),
                owner: account.owner.0.to_bytes().to_vec(),
                tree: account.tree.0.to_bytes().to_vec(),
                leaf_index: account.leaf_index.0 as i64,
                seq: account.seq.as_ref().map(|seq| seq.0 as i64),
                slot_created: account.slot_created.0 as i64,
                spent: false,     // Default value for new accounts (from persist logic)
                prev_spent: None, // Default value
                lamports: Decimal::from(account.lamports.0),
                discriminator: account
                    .data
                    .as_ref()
                    .map(|data| Decimal::from(data.discriminator.0)),
                tree_type: Some(context.tree_type as i32), // From account context
                nullified_in_tree: false, // Default value for new accounts (from persist logic)
                nullifier_queue_index: None, // Default value
                in_output_queue: context.in_output_queue, // From account context
                queue: context.queue.0.to_bytes().to_vec(), // Use queue from account context
                nullifier: None,          // Default value
                tx_hash: context.tx_hash.as_ref().map(|hash| hash.0.to_vec()),
            }
        })
        .collect();

    // Get all account hashes for the query
    let expected_hashes: Vec<Vec<u8>> = expected_models
        .iter()
        .map(|model| model.hash.clone())
        .collect();

    // Query database for accounts with matching hashes
    let mut db_accounts = accounts::Entity::find()
        .filter(accounts::Column::Hash.is_in(expected_hashes))
        .all(db_conn)
        .await?;

    // Sort both vectors by hash for consistent comparison
    let mut expected_models_sorted = expected_models;
    expected_models_sorted.sort_by(|a, b| a.hash.cmp(&b.hash));
    db_accounts.sort_by(|a, b| a.hash.cmp(&b.hash));

    // Single assert comparing the entire vectors
    assert_eq!(
        db_accounts, expected_models_sorted,
        "Database accounts do not match expected accounts"
    );

    println!(
        "✅ Successfully verified {} output accounts were persisted correctly",
        db_accounts.len()
    );
    println!("Database accounts: {:?}", db_accounts);
    println!("Expected accounts: {:?}", expected_models_sorted);
    Ok(())
}

/// Assert that all input accounts from the state update were marked as spent in the database
/// This function compares the complete account models, not just the spent flag
async fn assert_input_accounts_persisted(
    db_conn: &DatabaseConnection,
    metadata: &StateUpdateMetadata,
    state_update: &StateUpdate,
    pre_existing_models: &[photon_indexer::dao::generated::accounts::Model],
    _base_nullifier_queue_index: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use photon_indexer::dao::generated::accounts;
    use sea_orm::ColumnTrait;

    // Validate metadata matches actual state update
    let expected_total_in_accounts = metadata.in_accounts_v1_count + metadata.in_accounts_v2_count;
    assert_eq!(
        state_update.in_accounts.len(),
        expected_total_in_accounts,
        "Metadata in_accounts count ({}) doesn't match actual in_accounts ({})",
        expected_total_in_accounts,
        state_update.in_accounts.len()
    );

    // Validate we have the right number of pre-existing models
    assert_eq!(
        pre_existing_models.len(),
        expected_total_in_accounts,
        "Pre-existing models count ({}) doesn't match expected in_accounts ({})",
        pre_existing_models.len(),
        expected_total_in_accounts
    );

    if state_update.in_accounts.is_empty() {
        println!("✅ No input accounts - skipping input accounts verification");
        return Ok(());
    }

    // Validate v1/v2 split in pre-existing models matches metadata
    let actual_v1_input_count = pre_existing_models
        .iter()
        .filter(|model| model.tree_type == Some(1)) // TreeType::StateV1
        .count();
    let actual_v2_input_count = pre_existing_models
        .iter()
        .filter(|model| model.tree_type == Some(3)) // TreeType::StateV2
        .count();

    assert_eq!(
        actual_v1_input_count, metadata.in_accounts_v1_count,
        "Metadata v1 in_accounts count ({}) doesn't match actual v1 pre-existing count ({})",
        metadata.in_accounts_v1_count, actual_v1_input_count
    );

    assert_eq!(
        actual_v2_input_count, metadata.in_accounts_v2_count,
        "Metadata v2 in_accounts count ({}) doesn't match actual v2 pre-existing count ({})",
        metadata.in_accounts_v2_count, actual_v2_input_count
    );

    // Create expected models from pre-existing models with spent=true, prev_spent=original spent
    let mut expected_models: Vec<accounts::Model> = pre_existing_models
        .iter()
        .map(|model| {
            // For all accounts (v1 and v2), spend_input_accounts() sets:
            // - spent: true
            // - prev_spent: Some(original_spent)
            // v2-specific fields (nullifier_queue_index, tx_hash) are handled by BatchNullifyContext
            accounts::Model {
                spent: true,                   // Should be marked as spent
                prev_spent: Some(model.spent), // prev_spent should be the original spent value
                ..model.clone()                // All other fields should remain the same
            }
        })
        .collect();

    // Sort by hash for consistent comparison
    expected_models.sort_by(|a, b| a.hash.cmp(&b.hash));

    // Query database for accounts with matching hashes
    let input_hashes: Vec<Vec<u8>> = state_update
        .in_accounts
        .iter()
        .map(|hash| hash.0.to_vec())
        .collect();

    let mut db_accounts = accounts::Entity::find()
        .filter(accounts::Column::Hash.is_in(input_hashes))
        .all(db_conn)
        .await?;

    // Sort by hash for consistent comparison
    db_accounts.sort_by(|a, b| a.hash.cmp(&b.hash));

    // Verify we found all input accounts
    assert_eq!(
        db_accounts.len(),
        expected_models.len(),
        "Expected {} input accounts in database, found {}",
        expected_models.len(),
        db_accounts.len()
    );

    // Single assert comparing the complete models
    assert_eq!(
        db_accounts, expected_models,
        "Input accounts do not match expected complete models after spending"
    );

    println!(
        "✅ Successfully verified {} input accounts were marked as spent with complete models",
        db_accounts.len()
    );
    Ok(())
}

/// Assert that state tree root matches reference implementation after appending new hashes
async fn assert_state_tree_root(
    db_conn: &DatabaseConnection,
    metadata: &StateUpdateMetadata,
    state_update: &StateUpdate,
    v1_reference_tree: &mut MerkleTree<Poseidon>,
) -> Result<(), Box<dyn std::error::Error>> {
    use photon_indexer::dao::generated::state_trees;
    use sea_orm::ColumnTrait;

    // Validate metadata consistency (same as output accounts validation)
    let expected_total_out_accounts =
        metadata.out_accounts_v1_count + metadata.out_accounts_v2_count;
    assert_eq!(
        state_update.out_accounts.len(),
        expected_total_out_accounts,
        "State tree: Metadata out_accounts count ({}) doesn't match actual out_accounts ({})",
        expected_total_out_accounts,
        state_update.out_accounts.len()
    );

    if state_update.out_accounts.is_empty() {
        println!("✅ No output accounts - skipping state tree root verification");
        return Ok(());
    }

    // For now, only verify v1 accounts since we're using a single reference tree
    // Filter to only v1 accounts for tree root verification
    let v1_accounts: Vec<_> = state_update
        .out_accounts
        .iter()
        .filter(|acc| acc.context.tree_type == TreeType::StateV1 as u16)
        .collect();

    if v1_accounts.is_empty() {
        println!("✅ No v1 output accounts - skipping state tree root verification");
        return Ok(());
    }

    // Get the tree pubkey from the first v1 output account
    let tree_pubkey_bytes = v1_accounts[0].account.tree.0.to_bytes().to_vec();

    println!("V1 Account Hashes (should be in tree):");
    for account_with_context in &v1_accounts {
        let account_hash = hex::encode(account_with_context.account.hash.0);
        let leaf_index = account_with_context.account.leaf_index.0;
        println!("  V1 Hash({}) at leaf_index {}", account_hash, leaf_index);
    }

    // Also log V2 accounts for visibility (these go to output queue)
    let v2_accounts: Vec<_> = state_update
        .out_accounts
        .iter()
        .filter(|acc| acc.context.tree_type == TreeType::StateV2 as u16)
        .collect();

    if !v2_accounts.is_empty() {
        println!("V2 Account Hashes (go to output queue, not tree directly):");
        for account_with_context in &v2_accounts {
            let account_hash = hex::encode(account_with_context.account.hash.0);
            let leaf_index = account_with_context.account.leaf_index.0;
            println!("  V2 Hash({}) at leaf_index {}", account_hash, leaf_index);
        }
    }

    // First, get all leaf nodes from database to verify they match our V1 output accounts
    let leaf_nodes = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(tree_pubkey_bytes.clone()))
        .filter(state_trees::Column::Level.eq(0i64)) // Leaf level
        .all(db_conn)
        .await?;

    println!("Database Leaf Hashes (for V1 tree):");
    for leaf in &leaf_nodes {
        println!(
            "  Hash({}) at leaf_idx={:?}",
            hex::encode(&leaf.hash),
            leaf.leaf_idx
        );
    }

    // Assert that all our V1 account hashes are present as leaf nodes in the database
    for account_with_context in &v1_accounts {
        let account_hash = hex::encode(&account_with_context.account.hash.0);
        let leaf_index = account_with_context.account.leaf_index.0;

        let found_leaf = leaf_nodes.iter().find(|leaf| {
            leaf.leaf_idx == Some(leaf_index as i64) && hex::encode(&leaf.hash) == account_hash
        });

        assert!(
            found_leaf.is_some(),
            "V1 account hash {} at leaf_index {} not found in database leaf nodes",
            account_hash,
            leaf_index
        );
    }
    println!("✅ All V1 account hashes verified as leaf nodes in database");

    // Verify V2 accounts are NOT in the state tree (they should be in output queue only)
    if !v2_accounts.is_empty() {
        println!("Verifying V2 accounts are NOT in state tree (should be in output queue only):");
        for account_with_context in &v2_accounts {
            let account_hash = hex::encode(&account_with_context.account.hash.0);

            let found_leaf = leaf_nodes
                .iter()
                .find(|leaf| hex::encode(&leaf.hash) == account_hash);

            assert!(
                found_leaf.is_none(),
                "V2 account hash {} should NOT be found in state tree leaf nodes (should be in output queue only), but was found at leaf_idx={:?}",
                account_hash,
                found_leaf.map(|leaf| leaf.leaf_idx)
            );

            println!(
                "  ✅ V2 Hash({}) correctly NOT in state tree (in output queue)",
                account_hash
            );
        }
        println!(
            "✅ All V2 account hashes verified as NOT in state tree (correctly in output queue)"
        );
    }

    // Append only the V1 leaves from current state update to reference tree
    println!(
        "Appending {} V1 leaves from current state update to reference tree",
        v1_accounts.len()
    );

    for account_with_context in &v1_accounts {
        let leaf_hash = account_with_context.account.hash.0;
        v1_reference_tree.append(&leaf_hash)?;
    }

    // Get reference tree root after construction
    let reference_root = v1_reference_tree.root();
    println!("Reference tree root: {}", hex::encode(&reference_root));

    // Get database root node for comparison
    let all_nodes = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(tree_pubkey_bytes.clone()))
        .all(db_conn)
        .await?;

    let max_level = all_nodes.iter().map(|node| node.level).max().unwrap_or(0);
    let root_nodes: Vec<_> = all_nodes
        .iter()
        .filter(|node| node.level == max_level)
        .collect();

    assert_eq!(
        root_nodes.len(),
        1,
        "Expected exactly 1 root node, found {}",
        root_nodes.len()
    );

    let root_node = root_nodes[0];
    let mut db_root_array = [0u8; 32];
    db_root_array.copy_from_slice(&root_node.hash);
    println!("Database root: {}", hex::encode(&db_root_array));

    assert_eq!(
        reference_root,
        db_root_array,
        "State tree root mismatch!\nReference: {}\nDatabase:  {}",
        hex::encode(&reference_root),
        hex::encode(&db_root_array)
    );

    println!("✅ State tree root verification successful!");

    Ok(())
}

#[named]
#[rstest]
#[tokio::test]
#[serial]
async fn test_persist_empty_state_update(
    #[values(DatabaseBackend::Sqlite)] db_backend: DatabaseBackend,
) {
    // Set required environment variables
    env::set_var("MAINNET_RPC_URL", "https://api.mainnet-beta.solana.com");
    env::set_var("DEVNET_RPC_URL", "https://api.devnet.solana.com");

    // Set up deterministic randomness following the light-protocol pattern
    let mut thread_rng = ThreadRng::default();
    let random_seed = thread_rng.next_u64();
    let seed: u64 = random_seed; // Could optionally take seed as parameter
                                 // Keep this print so that in case the test fails
                                 // we can use the seed to reproduce the error.
    println!("\n\npersist_state_update test seed {}\n\n", seed);
    let mut _rng = StdRng::seed_from_u64(seed);

    let name = trim_test_name(function_name!());
    let setup = setup(name, db_backend).await;

    // Create an empty state update
    let empty_state_update = StateUpdate::default();

    // Call persist_state_update with empty state update and commit
    let result = persist_state_update_and_commit(&setup.db_conn, empty_state_update).await;

    // Should complete successfully
    assert!(result.is_ok());

    // Verify that key tables remain empty after persisting empty state update
    use photon_indexer::dao::generated::{account_transactions, accounts, transactions};

    let accounts_count = accounts::Entity::find()
        .count(setup.db_conn.as_ref())
        .await
        .unwrap();
    assert_eq!(accounts_count, 0, "Accounts table should be empty");

    let transactions_count = transactions::Entity::find()
        .count(setup.db_conn.as_ref())
        .await
        .unwrap();
    assert_eq!(transactions_count, 0, "Transactions table should be empty");

    let account_transactions_count = account_transactions::Entity::find()
        .count(setup.db_conn.as_ref())
        .await
        .unwrap();
    assert_eq!(
        account_transactions_count, 0,
        "Account transactions table should be empty"
    );
}

#[named]
#[rstest]
#[tokio::test]
#[serial]
async fn test_output_accounts(#[values(DatabaseBackend::Sqlite)] db_backend: DatabaseBackend) {
    // Set required environment variables
    env::set_var("MAINNET_RPC_URL", "https://api.mainnet-beta.solana.com");
    env::set_var("DEVNET_RPC_URL", "https://api.devnet.solana.com");

    let name = trim_test_name(function_name!());
    let setup = setup(name, db_backend).await;

    // Set up deterministic randomness following the light-protocol pattern
    let mut thread_rng = ThreadRng::default();
    let random_seed = thread_rng.next_u64();
    let seed: u64 = random_seed;
    println!("\n\nconfig structure test seed {}\n\n", seed);
    let mut rng = StdRng::seed_from_u64(seed);

    let mut v1_reference_tree = MerkleTree::<Poseidon>::new(26, 0);

    // Test that the new config structure works correctly
    let config = StateUpdateConfig::default();

    // Verify config structure values
    assert_eq!(config.in_accounts_v1.min_entries, 0);
    assert_eq!(config.in_accounts_v1.max_entries, 3);
    assert_eq!(config.in_accounts_v1.probability, 0.3);

    assert_eq!(config.in_accounts_v2.min_entries, 0);
    assert_eq!(config.in_accounts_v2.max_entries, 3);
    assert_eq!(config.in_accounts_v2.probability, 0.3);

    assert_eq!(config.out_accounts_v1.min_entries, 0);
    assert_eq!(config.out_accounts_v1.max_entries, 5);
    assert_eq!(config.out_accounts_v1.probability, 1.0);

    assert_eq!(config.out_accounts_v2.min_entries, 0);
    assert_eq!(config.out_accounts_v2.max_entries, 5);
    assert_eq!(config.out_accounts_v2.probability, 1.0);

    assert_eq!(config.transactions.min_entries, 0);
    assert_eq!(config.transactions.max_entries, 2);
    assert_eq!(config.transactions.probability, 0.0);

    // Test that we can create a state update with incremental values
    let mut base_seq_v1 = 500;
    let mut base_leaf_index_v1 = 0;
    let mut base_leaf_index_v2 = 1000; // Use separate leaf index space for v2
    let mut base_nullifier_queue_index = 0; // Track nullifier queue position for v2 input accounts
    let mut v1_available_accounts_for_spending: Vec<Hash> = Vec::new();
    let mut v2_available_accounts_for_spending: Vec<Hash> = Vec::new();
    let num_iters = 100;

    // Steps:
    // 1. Generate random state update
    // 2. Fetch pre-existing account models for input accounts before persisting
    // 3. Persist the simple state update
    // 4. Assert output accounts
    // 5. Assert input accounts
    // 6. Assert state tree root matches reference tree root
    // 7. Update test state
    for slot in 0..num_iters {
        println!("iter {}", slot);
        // 1. Generate random state update
        let (state_update, metadata) = get_rnd_state_update(
            &mut rng,
            &config,
            slot,
            base_seq_v1,
            base_leaf_index_v1,
            base_leaf_index_v2,
            base_nullifier_queue_index,
            &mut v1_available_accounts_for_spending,
            &mut v2_available_accounts_for_spending,
        );
        println!("state_update {:?}", state_update);

        // 2. Fetch pre-existing account models for input accounts before persisting
        let pre_existing_input_models =
            fetch_pre_existing_input_models(setup.db_conn.as_ref(), &state_update)
                .await
                .expect("Failed to fetch pre-existing input accounts");

        // 3. Persist the random state update
        let result = persist_state_update_and_commit(&setup.db_conn, state_update.clone()).await;

        // Should complete successfully
        assert!(
            result.is_ok(),
            "Failed to persist random state update: {:?}",
            result.err()
        );

        // 4. Assert that all output accounts were persisted correctly
        assert_output_accounts_persisted(&setup.db_conn, &metadata, &state_update)
            .await
            .expect("Failed to verify output accounts persistence");

        // 5. Assert that all input accounts were marked as spent with complete models
        assert_input_accounts_persisted(
            &setup.db_conn,
            &metadata,
            &state_update,
            &pre_existing_input_models,
            base_nullifier_queue_index,
        )
        .await
        .expect("Failed to verify input accounts persistence");

        // 6. Assert that state tree root matches reference tree root
        // - updates reference tree
        assert_state_tree_root(
            &setup.db_conn,
            &metadata,
            &state_update,
            &mut v1_reference_tree,
        )
        .await
        .expect("Failed to verify state tree root");

        // 7. Update test state after processing the state update
        update_test_state_after_iteration(
            &state_update,
            &metadata,
            &mut v1_available_accounts_for_spending,
            &mut v2_available_accounts_for_spending,
            &mut base_seq_v1,
            &mut base_leaf_index_v1,
            &mut base_leaf_index_v2,
            &mut base_nullifier_queue_index,
        );
    }
    println!("Config structure test completed successfully - unified CollectionConfig approach with incremental slot/seq/leaf_index working");
}
