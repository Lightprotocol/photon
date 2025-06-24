use crate::utils::*;
use function_name::named;
use photon_indexer::common::typedefs::account::{Account, AccountContext, AccountWithContext};
use photon_indexer::common::typedefs::account::AccountData;
use photon_indexer::common::typedefs::bs64_string::Base64String;
use photon_indexer::common::typedefs::hash::Hash;
use photon_indexer::common::typedefs::serializable_pubkey::SerializablePubkey;
use photon_indexer::common::typedefs::unsigned_integer::UnsignedInteger;
use photon_indexer::ingester::parser::indexer_events::RawIndexedElement;
use photon_indexer::ingester::parser::state_update::{
    AccountTransaction, AddressQueueUpdate, IndexedTreeLeafUpdate, LeafNullification, StateUpdate, Transaction
};
use photon_indexer::ingester::persist::persist_state_update;
use light_compressed_account::indexer_event::event::BatchNullifyContext;
use rand::{rngs::{StdRng, ThreadRng}, Rng, RngCore, SeedableRng};
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait, TransactionTrait};
use serial_test::serial;
use solana_pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::env;

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

/// Configuration for generating random StateUpdate data
#[derive(Debug, Clone)]
pub struct StateUpdateConfig {
    // Collection configurations for StateUpdate fields
    pub in_accounts: CollectionConfig,
    pub out_accounts: CollectionConfig,
    pub account_transactions: CollectionConfig,
    pub transactions: CollectionConfig,
    pub leaf_nullifications: CollectionConfig,
    pub indexed_merkle_tree_updates: CollectionConfig,
    pub batch_nullify_context: CollectionConfig,
    pub batch_new_addresses: CollectionConfig,
    
    // Value ranges for various types
    pub lamports_min: u64,
    pub lamports_max: u64,
    pub slot_min: u64,
    pub slot_max: u64,
    pub seq_min: u64,
    pub seq_max: u64,
    pub leaf_index_min: u64,
    pub leaf_index_max: u64,
    pub data_size_min: usize,
    pub data_size_max: usize,
}

impl Default for StateUpdateConfig {
    fn default() -> Self {
        Self {
            in_accounts: CollectionConfig::new(0, 5, 0.7),
            out_accounts: CollectionConfig::new(0, 5, 0.8),
            account_transactions: CollectionConfig::new(0, 3, 0.6),
            transactions: CollectionConfig::new(0, 2, 0.9),
            leaf_nullifications: CollectionConfig::new(0, 3, 0.5),
            indexed_merkle_tree_updates: CollectionConfig::new(0, 3, 0.4),
            batch_nullify_context: CollectionConfig::new(0, 2, 0.3),
            batch_new_addresses: CollectionConfig::new(0, 3, 0.6),
            
            lamports_min: 1000,
            lamports_max: 1_000_000,
            slot_min: 0,
            slot_max: 10_000,
            seq_min: 0,
            seq_max: 10_000,
            leaf_index_min: 0,
            leaf_index_max: 100,
            data_size_min: 0,
            data_size_max: 100,
        }
    }
}

/// Generate a random StateUpdate following the light-protocol pattern
fn get_rnd_state_update(rng: &mut StdRng, config: &StateUpdateConfig) -> StateUpdate {
    let mut state_update = StateUpdate::default();
    
    // Generate in_accounts (HashSet<Hash>)
    if rng.gen_bool(config.in_accounts.probability) {
        let count = rng.gen_range(config.in_accounts.min_entries..=config.in_accounts.max_entries);
        for _ in 0..count {
            state_update.in_accounts.insert(Hash::new_unique());
        }
    }
    
    // Generate out_accounts (Vec<AccountWithContext>)
    if rng.gen_bool(config.out_accounts.probability) {
        let count = rng.gen_range(config.out_accounts.min_entries..=config.out_accounts.max_entries);
        for _ in 0..count {
            let account = AccountWithContext {
                account: Account {
                    hash: Hash::new_unique(),
                    address: if rng.gen_bool(0.7) { Some(SerializablePubkey::new_unique()) } else { None },
                    data: if rng.gen_bool(0.6) {
                        let data_size = rng.gen_range(config.data_size_min..=config.data_size_max);
                        Some(AccountData {
                            discriminator: UnsignedInteger(rng.gen()),
                            data: Base64String((0..data_size).map(|_| rng.gen()).collect()),
                            data_hash: Hash::new_unique(),
                        })
                    } else { None },
                    owner: SerializablePubkey::new_unique(),
                    lamports: UnsignedInteger(rng.gen_range(config.lamports_min..=config.lamports_max)),
                    tree: SerializablePubkey::new_unique(),
                    leaf_index: UnsignedInteger(rng.gen_range(config.leaf_index_min..=config.leaf_index_max)),
                    seq: Some(UnsignedInteger(rng.gen_range(config.seq_min..=config.seq_max))),
                    slot_created: UnsignedInteger(rng.gen_range(config.slot_min..=config.slot_max)),
                },
                context: AccountContext::default(),
            };
            state_update.out_accounts.push(account);
        }
    }
    
    // Generate account_transactions (HashSet<AccountTransaction>)
    if rng.gen_bool(config.account_transactions.probability) {
        let count = rng.gen_range(config.account_transactions.min_entries..=config.account_transactions.max_entries);
        for _ in 0..count {
            let mut sig_bytes = [0u8; 64];
            rng.fill(&mut sig_bytes);
            state_update.account_transactions.insert(AccountTransaction {
                hash: Hash::new_unique(),
                signature: Signature::from(sig_bytes),
            });
        }
    }
    
    // Generate transactions (HashSet<Transaction>)
    if rng.gen_bool(config.transactions.probability) {
        let count = rng.gen_range(config.transactions.min_entries..=config.transactions.max_entries);
        for _ in 0..count {
            let mut sig_bytes = [0u8; 64];
            rng.fill(&mut sig_bytes);
            state_update.transactions.insert(Transaction {
                signature: Signature::from(sig_bytes),
                slot: rng.gen_range(config.slot_min..=config.slot_max),
                uses_compression: rng.gen(),
                error: if rng.gen_bool(0.1) { Some("Random error".to_string()) } else { None },
            });
        }
    }
    
    // Generate leaf_nullifications (HashSet<LeafNullification>)
    if rng.gen_bool(config.leaf_nullifications.probability) {
        let count = rng.gen_range(config.leaf_nullifications.min_entries..=config.leaf_nullifications.max_entries);
        for _ in 0..count {
            let mut sig_bytes = [0u8; 64];
            rng.fill(&mut sig_bytes);
            state_update.leaf_nullifications.insert(LeafNullification {
                tree: Pubkey::new_unique(),
                leaf_index: rng.gen_range(config.leaf_index_min..=config.leaf_index_max),
                seq: rng.gen_range(config.seq_min..=config.seq_max),
                signature: Signature::from(sig_bytes),
            });
        }
    }
    
    // Generate indexed_merkle_tree_updates (HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>)
    if rng.gen_bool(config.indexed_merkle_tree_updates.probability) {
        let count = rng.gen_range(config.indexed_merkle_tree_updates.min_entries..=config.indexed_merkle_tree_updates.max_entries);
        for _ in 0..count {
            let tree = Pubkey::new_unique();
            let index = rng.gen_range(config.leaf_index_min..=config.leaf_index_max);
            let update = IndexedTreeLeafUpdate {
                tree,
                leaf: RawIndexedElement {
                    value: rng.gen::<[u8; 32]>(),
                    next_index: rng.gen::<u32>() as usize,
                    next_value: rng.gen::<[u8; 32]>(),
                    index: rng.gen::<u32>() as usize,
                },
                hash: rng.gen::<[u8; 32]>(),
                seq: rng.gen_range(config.seq_min..=config.seq_max),
            };
            state_update.indexed_merkle_tree_updates.insert((tree, index), update);
        }
    }
    
    // Generate batch_nullify_context (Vec<BatchNullifyContext>)
    if rng.gen_bool(config.batch_nullify_context.probability) {
        let count = rng.gen_range(config.batch_nullify_context.min_entries..=config.batch_nullify_context.max_entries);
        for _ in 0..count {
            state_update.batch_nullify_context.push(BatchNullifyContext {
                tx_hash: rng.gen::<[u8; 32]>(),
                account_hash: rng.gen::<[u8; 32]>(),
                nullifier: rng.gen::<[u8; 32]>(),
                nullifier_queue_index: rng.gen_range(0..=1000),
            });
        }
    }
    
    // Generate batch_new_addresses (Vec<AddressQueueUpdate>)
    if rng.gen_bool(config.batch_new_addresses.probability) {
        let count = rng.gen_range(config.batch_new_addresses.min_entries..=config.batch_new_addresses.max_entries);
        for _ in 0..count {
            state_update.batch_new_addresses.push(AddressQueueUpdate {
                tree: SerializablePubkey::new_unique(),
                address: rng.gen::<[u8; 32]>(),
                queue_index: rng.gen_range(0..=1000),
            });
        }
    }
    
    // Note: batch_merkle_tree_events is left as default since it's complex and rarely used
    
    state_update
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
async fn test_config_structure(
    #[values(DatabaseBackend::Sqlite)] db_backend: DatabaseBackend,
) {
    // Set required environment variables
    env::set_var("MAINNET_RPC_URL", "https://api.mainnet-beta.solana.com");
    env::set_var("DEVNET_RPC_URL", "https://api.devnet.solana.com");
    
    let name = trim_test_name(function_name!());
    let setup = setup(name, db_backend).await;

    // Test that the new config structure works correctly
    let config = StateUpdateConfig::default();
    
    // Verify config structure values
    assert_eq!(config.in_accounts.min_entries, 0);
    assert_eq!(config.in_accounts.max_entries, 5);
    assert_eq!(config.in_accounts.probability, 0.7);
    
    assert_eq!(config.out_accounts.min_entries, 0);
    assert_eq!(config.out_accounts.max_entries, 5);
    assert_eq!(config.out_accounts.probability, 0.8);
    
    assert_eq!(config.transactions.min_entries, 0);
    assert_eq!(config.transactions.max_entries, 2);
    assert_eq!(config.transactions.probability, 0.9);
    
    println!("Config structure test completed successfully - unified CollectionConfig approach working");
}
