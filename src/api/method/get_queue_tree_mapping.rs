use crate::ingester::parser::tree_info::{TreeInfo, QUEUE_TREE_MAPPING};
use light_compressed_account::TreeType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SerializableTreeInfo {
    pub tree: String,
    pub queue: String,
    pub height: u32,
    pub tree_type: String,
}

impl From<&TreeInfo> for SerializableTreeInfo {
    fn from(info: &TreeInfo) -> Self {
        SerializableTreeInfo {
            tree: info.tree.to_string(),
            queue: info.queue.to_string(),
            height: info.height,
            tree_type: match info.tree_type {
                TreeType::StateV1 => "StateV1".to_string(),
                TreeType::StateV2 => "StateV2".to_string(),
                TreeType::AddressV1 => "AddressV1".to_string(),
                TreeType::AddressV2 => "AddressV2".to_string(),
                _ => "Unknown".to_string(),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct QueueTreeMappingResponse {
    pub mapping: HashMap<String, SerializableTreeInfo>,
}

pub async fn get_queue_tree_mapping() -> QueueTreeMappingResponse {
    let mut mapping = HashMap::new();

    for (key, value) in QUEUE_TREE_MAPPING.iter() {
        mapping.insert(key.clone(), SerializableTreeInfo::from(value));
    }

    QueueTreeMappingResponse { mapping }
}
