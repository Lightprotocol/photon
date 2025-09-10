use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "queue_hash_chains")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tree_pubkey: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub queue_type: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub batch_start_index: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub zkp_batch_index: i32,
    pub start_offset: i64,
    pub hash_chain: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
