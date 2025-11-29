use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn execute_sql(manager: &SchemaManager<'_>, sql: &str) -> Result<(), DbErr> {
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
        // Only apply to SQLite - PostgreSQL DECIMAL(23,0) already preserves u64 precision
        if manager.get_database_backend() != DatabaseBackend::Sqlite {
            return Ok(());
        }

        // SQLite stores REAL (64-bit float) which loses precision for u64 values > 2^53.
        // Convert affected columns from REAL to TEXT to preserve full u64 precision.
        // SeaORM's Decimal type maps to REAL in SQLite, causing precision loss.

        // Fix accounts table: lamports and discriminator columns
        execute_sql(
            manager,
            r#"
            CREATE TABLE accounts_precision_fix (
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
                lamports TEXT NOT NULL,
                discriminator TEXT,
                in_output_queue BOOLEAN NOT NULL DEFAULT TRUE,
                nullifier BLOB,
                tx_hash BLOB,
                nullifier_queue_index BIGINT NULL,
                nullified_in_tree BOOLEAN NOT NULL DEFAULT FALSE,
                tree_type INTEGER NULL
            );

            INSERT INTO accounts_precision_fix
            SELECT
                hash, data, data_hash, address, owner, tree, queue, leaf_index, seq,
                slot_created, spent, prev_spent,
                CAST(CAST(lamports AS INTEGER) AS TEXT) as lamports,
                CASE WHEN discriminator IS NOT NULL 
                     THEN CAST(CAST(discriminator AS INTEGER) AS TEXT)
                     ELSE NULL 
                END as discriminator,
                in_output_queue, nullifier, tx_hash, nullifier_queue_index,
                nullified_in_tree, tree_type
            FROM accounts;

            DROP TABLE accounts;
            ALTER TABLE accounts_precision_fix RENAME TO accounts;

            CREATE INDEX accounts_address_spent_idx ON accounts (address, seq);
            CREATE UNIQUE INDEX accounts_owner_hash_idx ON accounts (spent, owner, hash);
            CREATE INDEX accounts_queue_idx ON accounts (tree, in_output_queue, leaf_index) WHERE in_output_queue = 1;
            CREATE INDEX idx_accounts_tree_nullified_spent ON accounts (tree, nullified_in_tree, spent);
            CREATE INDEX idx_accounts_tree_nullifier_queue ON accounts (tree, nullifier_queue_index);
            "#,
        )
        .await?;

        // Fix token_accounts table: amount column
        execute_sql(
            manager,
            r#"
            CREATE TABLE token_accounts_precision_fix (
                hash BLOB NOT NULL PRIMARY KEY,
                owner BLOB NOT NULL,
                mint BLOB NOT NULL,
                delegate BLOB,
                state INTEGER NOT NULL,
                spent BOOLEAN NOT NULL,
                prev_spent BOOLEAN,
                amount TEXT NOT NULL,
                tlv BLOB,
                FOREIGN KEY (hash) REFERENCES accounts(hash) ON DELETE CASCADE
            );

            INSERT INTO token_accounts_precision_fix
            SELECT
                hash, owner, mint, delegate, state, spent, prev_spent,
                CAST(CAST(amount AS INTEGER) AS TEXT) as amount,
                tlv
            FROM token_accounts;

            DROP TABLE token_accounts;
            ALTER TABLE token_accounts_precision_fix RENAME TO token_accounts;

            CREATE UNIQUE INDEX token_accounts_owner_mint_hash_idx ON token_accounts (spent, owner, mint, hash);
            CREATE UNIQUE INDEX token_accounts_delegate_mint_hash_idx ON token_accounts (spent, delegate, mint, hash);
            "#,
        )
        .await?;

        // Fix owner_balances table: lamports column
        execute_sql(
            manager,
            r#"
            CREATE TABLE owner_balances_precision_fix (
                owner BLOB NOT NULL PRIMARY KEY,
                lamports TEXT NOT NULL
            );

            INSERT INTO owner_balances_precision_fix
            SELECT
                owner,
                CAST(CAST(lamports AS INTEGER) AS TEXT) as lamports
            FROM owner_balances;

            DROP TABLE owner_balances;
            ALTER TABLE owner_balances_precision_fix RENAME TO owner_balances;
            "#,
        )
        .await?;

        // Fix token_owner_balances table: amount column
        execute_sql(
            manager,
            r#"
            CREATE TABLE token_owner_balances_precision_fix (
                owner BLOB NOT NULL,
                mint BLOB NOT NULL,
                amount TEXT NOT NULL,
                PRIMARY KEY (owner, mint)
            );

            INSERT INTO token_owner_balances_precision_fix
            SELECT
                owner, mint,
                CAST(CAST(amount AS INTEGER) AS TEXT) as amount
            FROM token_owner_balances;

            DROP TABLE token_owner_balances;
            ALTER TABLE token_owner_balances_precision_fix RENAME TO token_owner_balances;
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Only apply to SQLite
        if manager.get_database_backend() != DatabaseBackend::Sqlite {
            return Ok(());
        }

        // Rollback: Convert TEXT back to REAL (will lose precision again for large values)
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
                lamports REAL NOT NULL,
                discriminator REAL,
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
                CAST(lamports AS REAL) as lamports,
                CASE WHEN discriminator IS NOT NULL 
                     THEN CAST(discriminator AS REAL)
                     ELSE NULL 
                END as discriminator,
                in_output_queue, nullifier, tx_hash, nullifier_queue_index,
                nullified_in_tree, tree_type
            FROM accounts;

            DROP TABLE accounts;
            ALTER TABLE accounts_rollback RENAME TO accounts;

            CREATE INDEX accounts_address_spent_idx ON accounts (address, seq);
            CREATE UNIQUE INDEX accounts_owner_hash_idx ON accounts (spent, owner, hash);
            CREATE INDEX accounts_queue_idx ON accounts (tree, in_output_queue, leaf_index) WHERE in_output_queue = 1;
            CREATE INDEX idx_accounts_tree_nullified_spent ON accounts (tree, nullified_in_tree, spent);
            CREATE INDEX idx_accounts_tree_nullifier_queue ON accounts (tree, nullifier_queue_index);
            "#,
        )
        .await?;

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
                amount REAL NOT NULL,
                tlv BLOB,
                FOREIGN KEY (hash) REFERENCES accounts(hash) ON DELETE CASCADE
            );

            INSERT INTO token_accounts_rollback
            SELECT hash, owner, mint, delegate, state, spent, prev_spent,
                   CAST(amount AS REAL), tlv
            FROM token_accounts;

            DROP TABLE token_accounts;
            ALTER TABLE token_accounts_rollback RENAME TO token_accounts;

            CREATE UNIQUE INDEX token_accounts_owner_mint_hash_idx ON token_accounts (spent, owner, mint, hash);
            CREATE UNIQUE INDEX token_accounts_delegate_mint_hash_idx ON token_accounts (spent, delegate, mint, hash);
            "#,
        )
        .await?;

        execute_sql(
            manager,
            r#"
            CREATE TABLE owner_balances_rollback (
                owner BLOB NOT NULL PRIMARY KEY,
                lamports REAL NOT NULL
            );

            INSERT INTO owner_balances_rollback
            SELECT owner, CAST(lamports AS REAL) FROM owner_balances;

            DROP TABLE owner_balances;
            ALTER TABLE owner_balances_rollback RENAME TO owner_balances;
            "#,
        )
        .await?;

        execute_sql(
            manager,
            r#"
            CREATE TABLE token_owner_balances_rollback (
                owner BLOB NOT NULL,
                mint BLOB NOT NULL,
                amount REAL NOT NULL,
                PRIMARY KEY (owner, mint)
            );

            INSERT INTO token_owner_balances_rollback
            SELECT owner, mint, CAST(amount AS REAL) FROM token_owner_balances;

            DROP TABLE token_owner_balances;
            ALTER TABLE token_owner_balances_rollback RENAME TO token_owner_balances;
            "#,
        )
        .await?;

        Ok(())
    }
}
