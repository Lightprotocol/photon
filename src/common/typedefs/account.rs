use serde::Serialize;

use utoipa::ToSchema;

use super::{
    bs64_string::Base64String, hash::Hash, serializable_pubkey::SerializablePubkey,
    unsigned_integer::UnsignedInteger,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Account {
    pub hash: Hash,
    pub address: Option<SerializablePubkey>,
    pub data: Option<AccountData>,
    pub owner: SerializablePubkey,
    pub lamports: UnsignedInteger,
    pub tree: SerializablePubkey,
    pub leaf_index: UnsignedInteger,
    // For legacy trees is always Some() since the user tx appends directly to the Merkle tree
    // for batched tress:
    // 2.1. None when is in output queue
    // 2.2. Some once it was inserted into the Merkle tree from the output queue
    pub seq: Option<UnsignedInteger>,
    pub slot_created: UnsignedInteger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccountV2 {
    pub hash: Hash,
    pub address: Option<SerializablePubkey>,
    pub data: Option<AccountData>,
    pub owner: SerializablePubkey,
    pub lamports: UnsignedInteger,
    pub tree: SerializablePubkey,
    pub leaf_index: UnsignedInteger,
    // For legacy trees is always Some() since the user tx appends directly to the Merkle tree
    // for batched tress:
    // 2.1. None when is in output queue
    // 2.2. Some once it was inserted into the Merkle tree from the output queue
    pub seq: Option<UnsignedInteger>,
    pub slot_created: UnsignedInteger,
    // nullifier_queue in legacy trees, output_queue in V2 trees.
    pub queue: Option<SerializablePubkey>,
    // Indicates if the account is not yet provable by validity_proof. The
    // account resides in on-chain RAM, with leaf_index mapping to its position.
    // This allows the protocol to prove the account's validity using only the
    // leaf_index. Consumers use this to decide if a validity proof is needed,
    // saving one RPC roundtrip.
    pub prove_by_index: bool,
}

/// This is currently used internally:
/// - Internal (state_updates,..)
/// - GetTransactionWithCompressionInfo (internally)
/// - GetTransactionWithCompressionInfoV2 (internally)
/// All endpoints return AccountV2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccountContext {
    pub queue: Option<SerializablePubkey>,
    pub in_output_queue: bool,
    pub spent: bool,
    pub nullified_in_tree: bool,
    // if nullifier_queue_index is not None, then this account is in input queue
    // an account can be in the input and output queue at the same time.
    // an account that is in the input queue must have been in the output queue before or currently is in the output queue
    pub nullifier_queue_index: Option<UnsignedInteger>,
    // Legacy trees: None
    // Batched trees:
    // None if not inserted into input queue or inserted into merkle tree from input queue
    // Some(H(account_hash, leaf_index, tx_hash))
    pub nullifier: Option<Hash>,
    // tx_hash is:
    // Legacy: None
    // Batched: None if not inserted into input queue or inserted in tree from input queue, else Some(nullifier)
    pub tx_hash: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccountWithContext {
    pub account: Account,
    pub context: AccountContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccountData {
    pub discriminator: UnsignedInteger,
    pub data: Base64String,
    pub data_hash: Hash,
}
