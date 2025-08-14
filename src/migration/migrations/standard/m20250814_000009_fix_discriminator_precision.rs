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
            execute_sql(
                manager,
                r#"
                -- Fix discriminator precision loss by changing from REAL to TEXT
                -- Step 1: Create new table with TEXT discriminator column
                CREATE TABLE accounts_discriminator_fix (
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
                    lamports REAL,
                    discriminator TEXT,  -- Changed from REAL to TEXT
                    in_output_queue BOOLEAN NOT NULL DEFAULT TRUE,
                    nullifier BLOB,
                    tx_hash BLOB,
                    nullifier_queue_index BIGINT NULL,
                    nullified_in_tree BOOLEAN NOT NULL DEFAULT FALSE,
                    tree_type INTEGER NULL
                );

                -- Step 2: Copy data, converting REAL discriminator to TEXT
                -- Note: This will lose precision for existing corrupted data, 
                -- but new data will be stored correctly as TEXT
                INSERT INTO accounts_discriminator_fix
                SELECT
                    hash, data, data_hash, address, owner, tree, queue, leaf_index, seq,
                    slot_created, spent, prev_spent, lamports,
                    CASE 
                        WHEN discriminator IS NOT NULL THEN CAST(discriminator AS TEXT)
                        ELSE NULL 
                    END as discriminator,
                    in_output_queue, nullifier, tx_hash, nullifier_queue_index,
                    nullified_in_tree, tree_type
                FROM accounts;

                -- Step 3: Drop old table and rename new one
                DROP TABLE accounts;
                ALTER TABLE accounts_discriminator_fix RENAME TO accounts;

                -- Step 4: Recreate all indexes
                CREATE INDEX accounts_address_spent_idx ON accounts (address, seq);
                CREATE UNIQUE INDEX accounts_owner_hash_idx ON accounts (spent, owner, hash);
                CREATE INDEX accounts_queue_idx ON accounts (tree, in_output_queue, leaf_index) WHERE in_output_queue = 1;


                "#,
            )
            .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Rollback: Convert TEXT back to REAL (will cause precision loss again)
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            execute_sql(
                manager,
                r#"
                -- Rollback discriminator from TEXT to REAL
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
                    lamports REAL,
                    discriminator REAL,  -- Back to REAL
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
                    slot_created, spent, prev_spent, lamports,
                    CASE 
                        WHEN discriminator IS NOT NULL THEN CAST(discriminator AS REAL)
                        ELSE NULL 
                    END as discriminator,
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
        }

        Ok(())
    }
}
