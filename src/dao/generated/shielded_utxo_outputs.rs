//! Hand-written SeaORM entity for the `shielded_utxo_outputs` table.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "shielded_utxo_outputs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tx_signature: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub event_index: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub output_index: i16,
    pub slot: i64,
    #[sea_orm(unique)]
    pub utxo_hash: Vec<u8>,
    #[sea_orm(nullable)]
    pub utxo_tree: Option<Vec<u8>>,
    #[sea_orm(nullable)]
    pub leaf_index: Option<i64>,
    #[sea_orm(nullable)]
    pub tree_sequence: Option<i64>,
    pub encrypted_utxo: Vec<u8>,
    pub encrypted_utxo_hash: Vec<u8>,
    #[sea_orm(nullable)]
    pub fmd_clue: Option<Vec<u8>>,
    #[sea_orm(nullable)]
    pub zone_config_hash: Option<Vec<u8>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
