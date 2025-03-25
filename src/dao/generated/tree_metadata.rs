use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "tree_metadata")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub tree_pubkey: String,
    pub queue_pubkey: String,
    pub height: u32,
    pub tree_type: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Entity {
    pub fn find_by_tree_pubkey(tree_pubkey: &str) -> Select<Entity> {
        Self::find().filter(Column::TreePubkey.eq(tree_pubkey))
    }

    pub fn find_by_queue_pubkey(queue_pubkey: &str) -> Select<Entity> {
        Self::find().filter(Column::QueuePubkey.eq(queue_pubkey))
    }
}