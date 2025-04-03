use sea_orm_migration::{
    prelude::*,
    sea_orm::{Statement, ConnectionTrait},
};
use light_compressed_account::TreeType;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the tree_metadata table
        manager
            .create_table(
                Table::create()
                    .table(TreeMetadataSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TreeMetadataSchema::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TreeMetadataSchema::TreePubkey)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(TreeMetadataSchema::QueuePubkey).string().not_null())
                    .col(ColumnDef::new(TreeMetadataSchema::Height).integer().not_null())
                    .col(ColumnDef::new(TreeMetadataSchema::TreeType).integer().not_null())
                    .to_owned(),
            )
            .await?;

        // Create index on TreePubkey for fast lookups
        manager
            .create_index(
                Index::create()
                    .name(format!("idx-{}-tree-pubkey", TreeMetadataSchema::Table.to_string()).as_str())
                    .table(TreeMetadataSchema::Table)
                    .col(TreeMetadataSchema::TreePubkey)
                    .to_owned(),
            )
            .await?;

        // Create index on QueuePubkey for fast lookups
        manager
            .create_index(
                Index::create()
                    .name(format!("idx-{}-queue-pubkey", TreeMetadataSchema::Table.to_string()).as_str())
                    .table(TreeMetadataSchema::Table)
                    .col(TreeMetadataSchema::QueuePubkey)
                    .to_owned(),
            )
            .await?;
            
        // Now populate the table with predefined tree data using raw SQL
        // Get the actual table name from the Iden enum
        let table_name = TreeMetadataSchema::Table.to_string();
        
        // Define predefined tree data
        let predefined_trees = [
            // BatchedState tree
            (
                "HLKs5NJ8FXkJg8BrzJt56adFYYuwg5etzDtBbQYTsixu",
                "6L7SzhYB3anwEQ9cphpJ1U7Scwj57bx2xueReg7R9cKU",
                32,
                TreeType::BatchedState as i64
            ),
            // State trees
            (
                "smt1NamzXdq4AMqS2fS2F1i5KTYPZRhoHgWx38d8WsT",
                "nfq1NvQDJ2GEgnS8zt9prAe8rjjpAW1zFkrvZoBR148",
                26,
                TreeType::State as i64
            ),
            (
                "smt2rJAFdyJJupwMKAqTNAJwvjhmiZ4JYGZmbVRw1Ho",
                "nfq2hgS7NYemXsFaFUCe3EMXSDSfnZnAe27jC6aPP1X",
                26,
                TreeType::State as i64
            ),
            // Address tree
            (
                "amt1Ayt45jfbdw5YSo7iz6WZxUmnZsQTYXy82hVwyC2",
                "aq1S9z4reTSQAdgWHGD2zDaS39sjGrAxbR31vxJ2F4F",
                26,
                TreeType::Address as i64
            ),
        ];
        
        // Insert tree data 
        for (tree, queue, height, tree_type) in predefined_trees {
            let stmt = format!(
                "INSERT INTO {} (tree_pubkey, queue_pubkey, height, tree_type) VALUES ('{}', '{}', {}, {}) ON CONFLICT (tree_pubkey) DO NOTHING",
                table_name,
                tree,
                queue,
                height,
                tree_type
            );
            
            let res = manager.get_connection().execute(Statement::from_string(
                manager.get_database_backend(),
                stmt,
            )).await;
            
            if let Err(e) = res {
                // If error is not about duplicate, return it
                if !e.to_string().contains("duplicate") && !e.to_string().contains("UNIQUE") {
                    return Err(e);
                }
            }
        }
        
        // Create an index on QueuePubkey for faster lookups
        manager
            .create_index(
                Index::create()
                    .name(format!("idx-{}-queue-pubkey-lookup", table_name).as_str())
                    .table(TreeMetadataSchema::Table)
                    .col(TreeMetadataSchema::QueuePubkey)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop the table (which also removes all data)
        manager
            .drop_table(Table::drop().table(TreeMetadataSchema::Table).to_owned())
            .await
    }
}

/// Schema definition for the tree_metadata table
#[derive(Iden)]
enum TreeMetadataSchema {
    #[iden = "tree_metadata"]
    Table,
    Id,
    TreePubkey,
    QueuePubkey,
    Height,
    TreeType,
}