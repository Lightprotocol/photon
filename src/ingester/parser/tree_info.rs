use anyhow::Result;
use light_compressed_account::TreeType;
use sea_orm::{ConnectionTrait, EntityTrait, Set, DatabaseTransaction};
use solana_program::pubkey::Pubkey;

use crate::dao::generated::tree_metadata::{self, ActiveModel, Entity as TreeMetadata};
use crate::ingester::parser::indexer_events::MerkleTreeSequenceNumberV2;

pub const DEFAULT_TREE_HEIGHT: u32 = 32 + 1;

#[derive(Debug, Clone)]
pub struct TreeInfo {
    pub tree: Pubkey,
    pub queue: Pubkey,
    pub height: u32,
    pub tree_type: TreeType,
}

impl TreeInfo {
    
    pub fn from_sequence_number(seq_num: &MerkleTreeSequenceNumberV2) -> Self {
        Self {
            tree: seq_num.tree_pubkey,
            queue: seq_num.queue_pubkey,
            height: match TreeType::from(seq_num.tree_type) {
                TreeType::State => 26,
                TreeType::Address => 26,
                TreeType::BatchedState => 32,
                TreeType::BatchedAddress => 40,
            },
            tree_type: TreeType::from(seq_num.tree_type),
        }
    }
}

pub struct TreeInfoService;

impl TreeInfoService {
    
    pub async fn get_tree_info(conn: &impl ConnectionTrait, pubkey: &str) -> Result<Option<TreeInfo>> {
        if let Some(model) = TreeMetadata::find_by_tree_pubkey(pubkey)
            .one(conn)
            .await?
        {
            return Ok(Some(Self::model_to_tree_info(model)));
        }
        
        if let Some(model) = TreeMetadata::find_by_queue_pubkey(pubkey)
            .one(conn)
            .await?
        {
            return Ok(Some(Self::model_to_tree_info(model)));
        }
        
        Ok(None)
    }
    
    pub async fn save_tree_info(txn: &DatabaseTransaction, tree_info: &TreeInfo) -> Result<()> {
        let exists = TreeMetadata::find_by_tree_pubkey(&tree_info.tree.to_string())
            .one(txn)
            .await?
            .is_some();
            
        if !exists {
            let tree_metadata = ActiveModel {
                id: Default::default(),
                tree_pubkey: Set(tree_info.tree.to_string()),
                queue_pubkey: Set(tree_info.queue.to_string()),
                height: Set(tree_info.height),
                tree_type: Set(tree_info.tree_type as i64),
            };
            
            TreeMetadata::insert(tree_metadata).exec(txn).await?;
        }
        
        Ok(())
    }
    
    fn model_to_tree_info(model: tree_metadata::Model) -> TreeInfo {
        TreeInfo {
            tree: model.tree_pubkey.parse().unwrap_or_default(),
            queue: model.queue_pubkey.parse().unwrap_or_default(),
            height: model.height,
            tree_type: TreeType::from(model.tree_type as u64),
        }
    }
    
    pub async fn get_tree_height(conn: &impl ConnectionTrait, pubkey: &str) -> Result<Option<u32>> {
        Ok(Self::get_tree_info(conn, pubkey).await?.map(|x| x.height + 1))
    }
    
    pub async fn save_from_sequence_number(txn: &DatabaseTransaction, seq_num: &MerkleTreeSequenceNumberV2) -> Result<()> {
        let tree_info = TreeInfo::from_sequence_number(seq_num);
        Self::save_tree_info(txn, &tree_info).await
    }
}
