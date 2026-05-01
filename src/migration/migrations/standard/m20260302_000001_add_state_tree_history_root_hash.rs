use sea_orm_migration::prelude::*;

use super::super::super::model::table::StateTreeHistories;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(StateTreeHistories::Table)
                    .add_column(ColumnDef::new(StateTreeHistories::RootHash).binary().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(StateTreeHistories::Table)
                    .drop_column(StateTreeHistories::RootHash)
                    .to_owned(),
            )
            .await
    }
}
