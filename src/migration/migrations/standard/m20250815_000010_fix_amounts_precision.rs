use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn execute_sql<'a>(manager: &SchemaManager<'_>, sql: &str) -> Result<(), DbErr> {
    manager
        .get_connection()
        .execute(Statement::from_string(
            manager.get_database_backend(),
            sql.to_string(),
        ))
        .await?;
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Only apply this migration to SQLite - PostgreSQL already uses correct bigint2 type
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            // Fix lamports in accounts table
            execute_sql(
                manager,
                r#"
                -- Fix lamports precision loss by changing from REAL to TEXT
                -- Step 1: Create new table with TEXT lamports column
                CREATE TABLE accounts_lamports_fix (
                    hash BLOB NOT NULL PRIMARY KEY,
                    data BLOB,
                    data_hash BLOB,
                    address BLOB,
                    owner BLOB NOT NULL,
                    tree BLOB NOT NULL,
                    queue BLOB NULL,
                    leaf_index BIGINT NOT NULL,
                    seq BIGINT,
                    slot_created BIGINT NOT NULL,
                    spent BOOLEAN NOT NULL,
                    prev_spent BOOLEAN,
                    lamports TEXT,  -- Changed from REAL to TEXT
                    discriminator TEXT,
                    in_output_queue BOOLEAN NOT NULL DEFAULT TRUE,
                    nullifier BLOB,
                    tx_hash BLOB,
                    nullifier_queue_index BIGINT NULL,
                    nullified_in_tree BOOLEAN NOT NULL DEFAULT FALSE,
                    tree_type INTEGER NULL
                );

                -- Step 2: Copy data, converting REAL lamports to TEXT
                INSERT INTO accounts_lamports_fix
                SELECT
                    hash, data, data_hash, address, owner, tree, queue, leaf_index, seq,
                    slot_created, spent, prev_spent,
                    CASE 
                        WHEN lamports IS NOT NULL THEN CAST(CAST(lamports AS INTEGER) AS TEXT)
                        ELSE NULL 
                    END as lamports,
                    discriminator,
                    in_output_queue, nullifier, tx_hash, nullifier_queue_index,
                    nullified_in_tree, tree_type
                FROM accounts;

                -- Step 3: Drop old table and rename new one
                DROP TABLE accounts;
                ALTER TABLE accounts_lamports_fix RENAME TO accounts;

                -- Step 4: Recreate all indexes
                CREATE INDEX accounts_address_spent_idx ON accounts (address, seq);
                CREATE UNIQUE INDEX accounts_owner_hash_idx ON accounts (spent, owner, hash);
                CREATE INDEX accounts_queue_idx ON accounts (tree, in_output_queue, leaf_index) WHERE in_output_queue = 1;
                "#,
            )
            .await?;

            // Fix amount in token_accounts table
            execute_sql(
                manager,
                r#"
                -- Fix amount precision loss in token_accounts
                CREATE TABLE token_accounts_amount_fix (
                    hash BLOB NOT NULL PRIMARY KEY,
                    owner BLOB NOT NULL,
                    mint BLOB NOT NULL,
                    delegate BLOB,
                    state INTEGER NOT NULL,
                    spent BOOLEAN NOT NULL,
                    prev_spent BOOLEAN,
                    amount TEXT,  -- Changed from REAL to TEXT
                    tlv BLOB,
                    FOREIGN KEY (hash) REFERENCES accounts(hash) ON DELETE CASCADE
                );

                INSERT INTO token_accounts_amount_fix
                SELECT
                    hash, owner, mint, delegate, state, spent, prev_spent,
                    CASE 
                        WHEN amount IS NOT NULL THEN CAST(CAST(amount AS INTEGER) AS TEXT)
                        ELSE NULL 
                    END as amount,
                    tlv
                FROM token_accounts;

                DROP TABLE token_accounts;
                ALTER TABLE token_accounts_amount_fix RENAME TO token_accounts;

                -- Recreate indexes
                CREATE UNIQUE INDEX token_accounts_owner_mint_hash_idx ON token_accounts (spent, owner, mint, hash);
                CREATE UNIQUE INDEX token_accounts_delegate_mint_hash_idx ON token_accounts (spent, delegate, mint, hash);
                "#,
            )
            .await?;

            // Fix lamports in owner_balances table
            execute_sql(
                manager,
                r#"
                -- Fix lamports precision loss in owner_balances
                CREATE TABLE owner_balances_lamports_fix (
                    owner BLOB NOT NULL PRIMARY KEY,
                    lamports TEXT  -- Changed from REAL to TEXT
                );

                INSERT INTO owner_balances_lamports_fix
                SELECT
                    owner,
                    CASE 
                        WHEN lamports IS NOT NULL THEN CAST(CAST(lamports AS INTEGER) AS TEXT)
                        ELSE '0'
                    END as lamports
                FROM owner_balances;

                DROP TABLE owner_balances;
                ALTER TABLE owner_balances_lamports_fix RENAME TO owner_balances;
                "#,
            )
            .await?;

            // Fix amount in token_owner_balances table
            execute_sql(
                manager,
                r#"
                -- Fix amount precision loss in token_owner_balances
                CREATE TABLE token_owner_balances_amount_fix (
                    owner BLOB NOT NULL,
                    mint BLOB NOT NULL,
                    amount TEXT,  -- Changed from REAL to TEXT
                    PRIMARY KEY (owner, mint)
                );

                INSERT INTO token_owner_balances_amount_fix
                SELECT
                    owner, mint,
                    CASE 
                        WHEN amount IS NOT NULL THEN CAST(CAST(amount AS INTEGER) AS TEXT)
                        ELSE '0'
                    END as amount
                FROM token_owner_balances;

                DROP TABLE token_owner_balances;
                ALTER TABLE token_owner_balances_amount_fix RENAME TO token_owner_balances;
                "#,
            )
            .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Rollback: Convert TEXT back to REAL (will cause precision loss again)
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            // Rollback accounts table
            execute_sql(
                manager,
                r#"
                CREATE TABLE accounts_rollback (
                    hash BLOB NOT NULL PRIMARY KEY,
                    data BLOB,
                    data_hash BLOB,
                    address BLOB,
                    owner BLOB NOT NULL,
                    tree BLOB NOT NULL,
                    queue BLOB NULL,
                    leaf_index BIGINT NOT NULL,
                    seq BIGINT,
                    slot_created BIGINT NOT NULL,
                    spent BOOLEAN NOT NULL,
                    prev_spent BOOLEAN,
                    lamports REAL,  -- Back to REAL
                    discriminator TEXT,
                    in_output_queue BOOLEAN NOT NULL DEFAULT TRUE,
                    nullifier BLOB,
                    tx_hash BLOB,
                    nullifier_queue_index BIGINT NULL,
                    nullified_in_tree BOOLEAN NOT NULL DEFAULT FALSE,
                    tree_type INTEGER NULL
                );

                INSERT INTO accounts_rollback
                SELECT
                    hash, data, data_hash, address, owner, tree, queue, leaf_index, seq,
                    slot_created, spent, prev_spent,
                    CASE 
                        WHEN lamports IS NOT NULL THEN CAST(lamports AS REAL)
                        ELSE NULL 
                    END as lamports,
                    discriminator,
                    in_output_queue, nullifier, tx_hash, nullifier_queue_index,
                    nullified_in_tree, tree_type
                FROM accounts;

                DROP TABLE accounts;
                ALTER TABLE accounts_rollback RENAME TO accounts;

                -- Recreate indexes
                CREATE INDEX accounts_address_spent_idx ON accounts (address, seq);
                CREATE UNIQUE INDEX accounts_owner_hash_idx ON accounts (spent, owner, hash);
                CREATE INDEX accounts_queue_idx ON accounts (tree, in_output_queue, leaf_index) WHERE in_output_queue = 1;
                "#,
            )
            .await?;

            // Rollback token_accounts table
            execute_sql(
                manager,
                r#"
                CREATE TABLE token_accounts_rollback (
                    hash BLOB NOT NULL PRIMARY KEY,
                    owner BLOB NOT NULL,
                    mint BLOB NOT NULL,
                    delegate BLOB,
                    state INTEGER NOT NULL,
                    spent BOOLEAN NOT NULL,
                    prev_spent BOOLEAN,
                    amount REAL,  -- Back to REAL
                    tlv BLOB,
                    FOREIGN KEY (hash) REFERENCES accounts(hash) ON DELETE CASCADE
                );

                INSERT INTO token_accounts_rollback
                SELECT
                    hash, owner, mint, delegate, state, spent, prev_spent,
                    CASE 
                        WHEN amount IS NOT NULL THEN CAST(amount AS REAL)
                        ELSE NULL 
                    END as amount,
                    tlv
                FROM token_accounts;

                DROP TABLE token_accounts;
                ALTER TABLE token_accounts_rollback RENAME TO token_accounts;

                -- Recreate indexes
                CREATE UNIQUE INDEX token_accounts_owner_mint_hash_idx ON token_accounts (spent, owner, mint, hash);
                CREATE UNIQUE INDEX token_accounts_delegate_mint_hash_idx ON token_accounts (spent, delegate, mint, hash);
                "#,
            )
            .await?;

            // Rollback owner_balances table
            execute_sql(
                manager,
                r#"
                CREATE TABLE owner_balances_rollback (
                    owner BLOB NOT NULL PRIMARY KEY,
                    lamports REAL  -- Back to REAL
                );

                INSERT INTO owner_balances_rollback
                SELECT
                    owner,
                    CASE 
                        WHEN lamports IS NOT NULL THEN CAST(lamports AS REAL)
                        ELSE 0
                    END as lamports
                FROM owner_balances;

                DROP TABLE owner_balances;
                ALTER TABLE owner_balances_rollback RENAME TO owner_balances;
                "#,
            )
            .await?;

            // Rollback token_owner_balances table
            execute_sql(
                manager,
                r#"
                CREATE TABLE token_owner_balances_rollback (
                    owner BLOB NOT NULL,
                    mint BLOB NOT NULL,
                    amount REAL,  -- Back to REAL
                    PRIMARY KEY (owner, mint)
                );

                INSERT INTO token_owner_balances_rollback
                SELECT
                    owner, mint,
                    CASE 
                        WHEN amount IS NOT NULL THEN CAST(amount AS REAL)
                        ELSE 0
                    END as amount
                FROM token_owner_balances;

                DROP TABLE token_owner_balances;
                ALTER TABLE token_owner_balances_rollback RENAME TO token_owner_balances;
                "#,
            )
            .await?;
        }

        Ok(())
    }
}
