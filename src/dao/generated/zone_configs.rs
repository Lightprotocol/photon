//! Hand-written SeaORM entity for the `zone_configs` table.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "zone_configs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub zone_config_hash: Vec<u8>,
    pub first_seen_slot: i64,
    pub last_seen_slot: i64,
    #[sea_orm(nullable)]
    pub metadata: Option<Vec<u8>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
