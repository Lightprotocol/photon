//! Hand-written SeaORM entity for the `shielded_nullifier_events` table.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "shielded_nullifier_events")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub nullifier: Vec<u8>,
    pub nullifier_tree: Vec<u8>,
    pub tx_signature: Vec<u8>,
    pub event_index: i32,
    pub slot: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
