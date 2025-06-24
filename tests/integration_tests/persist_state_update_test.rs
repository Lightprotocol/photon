use crate::utils::*;
use function_name::named;
use photon_indexer::ingester::parser::state_update::StateUpdate;
use photon_indexer::ingester::persist::persist_state_update;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait, TransactionTrait};
use serial_test::serial;
use std::env;

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
