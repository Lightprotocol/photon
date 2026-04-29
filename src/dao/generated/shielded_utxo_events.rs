//! Hand-written SeaORM entity for the `shielded_utxo_events` table.
//! Mirrors the migration in
//! `migration/migrations/standard/m20260301_000001_add_shielded_pool_tables.rs`.
//! Public ciphertext + commitments only — never plaintext UTXO content.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "shielded_utxo_events")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tx_signature: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub event_index: i32,
    pub slot: i64,
    pub version: i16,
    pub instruction_tag: i16,
    pub tx_kind: i16,
    pub protocol_config: Vec<u8>,
    #[sea_orm(nullable)]
    pub zone_config_hash: Option<Vec<u8>>,
    pub tx_ephemeral_pubkey: Vec<u8>,
    pub encrypted_tx_ephemeral_keys: Vec<u8>,
    pub operation_commitment: Vec<u8>,
    #[sea_orm(nullable)]
    pub public_inputs_hash: Option<Vec<u8>>,
    #[sea_orm(nullable)]
    pub utxo_public_inputs_hash: Option<Vec<u8>>,
    #[sea_orm(nullable)]
    pub tree_public_inputs_hash: Option<Vec<u8>>,
    #[sea_orm(nullable)]
    pub nullifier_chain: Option<Vec<u8>>,
    pub input_nullifiers: Vec<u8>,
    #[sea_orm(nullable)]
    pub public_delta_mint: Option<Vec<u8>>,
    pub public_delta_spl: Vec<u8>,
    pub public_delta_sol: Vec<u8>,
    #[sea_orm(nullable)]
    pub relayer_fee: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
