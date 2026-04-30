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
    pub compressed_output_index: i32,
    pub slot: i64,
    #[sea_orm(unique)]
    pub utxo_hash: Vec<u8>,
    pub compressed_account_hash: Vec<u8>,
    pub utxo_tree: Vec<u8>,
    pub leaf_index: i64,
    pub tree_sequence: i64,
    pub encrypted_utxo: Vec<u8>,
    pub encrypted_utxo_hash: Vec<u8>,
    #[sea_orm(nullable)]
    pub zone_config_hash: Option<Vec<u8>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
