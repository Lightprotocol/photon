use crate::api::method::get_multiple_new_address_proofs::{
    get_multiple_new_address_proofs_helper, AddressProof, AddressWithTree,
    MerkleContextWithNewAddressProof,
};
use crate::api::method::get_validity_proof::prover::prove::generate_proof;
use crate::api::method::get_validity_proof::v1::GetValidityProofRequest;
use crate::api::method::get_validity_proof::CompressedProof;
use crate::common::typedefs::context::Context;
use crate::common::typedefs::hash::Hash;
use crate::dao::generated::accounts;
use crate::ingester::parser::tree_info::TreeInfo;
use crate::ingester::persist::get_multiple_compressed_leaf_proofs;
use crate::{
    api::error::PhotonApiError, common::typedefs::serializable_pubkey::SerializablePubkey,
};
use borsh::BorshDeserialize;
use jsonrpsee_core::Serialize;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use sea_orm::{DatabaseBackend, DatabaseConnection, Statement, TransactionTrait};
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetValidityProofRequestV2 {
    #[serde(default)]
    pub hashes: Vec<Hash>,
    #[serde(default)]
    pub new_addresses_with_trees: Vec<AddressWithTree>,
}

impl From<GetValidityProofRequestV2> for GetValidityProofRequest {
    fn from(value: GetValidityProofRequestV2) -> Self {
        GetValidityProofRequest {
            hashes: value.hashes,
            new_addresses: vec![],
            new_addresses_with_trees: value.new_addresses_with_trees,
        }
    }
}

#[derive(Serialize, Deserialize, Default, ToSchema, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetValidityProofResponseV2 {
    pub value: CompressedProofWithContextV2,
    pub context: Context,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone, Eq, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
pub struct MerkleContextV2 {
    pub tree_type: u16,
    pub tree: SerializablePubkey,
    // nullifier_queue in V1 trees, output_queue in V2 trees.
    pub queue: SerializablePubkey,
    pub cpi_context: Option<SerializablePubkey>,
    pub next_tree_context: Option<TreeContextInfo>,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Default, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
pub struct TreeContextInfo {
    pub tree_type: u16,
    pub tree: SerializablePubkey,
    pub queue: SerializablePubkey,
    pub cpi_context: Option<SerializablePubkey>,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct CompressedProofWithContextV2 {
    pub compressed_proof: Option<CompressedProof>,
    pub accounts: Vec<AccountProofInputs>,
    pub addresses: Vec<AddressProofInputs>,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccountProofInputs {
    pub hash: String,
    pub root: String,
    pub root_index: RootIndex,
    pub leaf_index: u64,
    pub merkle_context: MerkleContextV2,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct AddressProofInputs {
    pub address: String,
    pub root: String,
    pub root_index: RootIndex,
    pub merkle_context: MerkleContextV2,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct RootIndex {
    pub root_index: u64,
    // if prove_by_index is true, ignore root_index and use 0
    pub prove_by_index: bool,
}

impl From<RootIndex> for Option<u64> {
    fn from(val: RootIndex) -> Option<u64> {
        match val.prove_by_index {
            true => None,
            false => Some(val.root_index),
        }
    }
}

impl From<Option<u64>> for RootIndex {
    fn from(val: Option<u64>) -> RootIndex {
        match val {
            Some(root_index) => RootIndex {
                root_index,
                prove_by_index: false,
            },
            None => RootIndex {
                root_index: 0,
                prove_by_index: true,
            },
        }
    }
}

pub async fn get_validity_proof_v2(
    conn: &DatabaseConnection,
    prover_url: &str,
    request: GetValidityProofRequestV2,
) -> Result<GetValidityProofResponseV2, PhotonApiError> {
    if request.hashes.is_empty() && request.new_addresses_with_trees.is_empty() {
        return Ok(GetValidityProofResponseV2::default());
    }

    let v2_context = Context::extract(conn).await?;

    let tx = conn.begin().await?;
    if tx.get_database_backend() == DatabaseBackend::Postgres {
        tx.execute(Statement::from_string(
            tx.get_database_backend(),
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;".to_string(),
        ))
        .await?;
    }

    let mut accounts_for_prove_by_index_inputs: Vec<Option<AccountProofInputs>> =
        vec![None; request.hashes.len()];
    let mut hashes_needing_full_proof: Vec<Hash> = Vec::new();
    let mut original_indices_for_full_proof_hashes: Vec<usize> = Vec::new();

    if !request.hashes.is_empty() {
        let input_hashes_as_bytes: Vec<Vec<u8>> =
            request.hashes.iter().map(|h| h.to_vec()).collect();
        let db_account_models_vec = accounts::Entity::find()
            .filter(
                accounts::Column::Hash
                    .is_in(input_hashes_as_bytes)
                    .and(accounts::Column::Spent.eq(false)),
            )
            .all(&tx)
            .await?;

        let mut model_map = db_account_models_vec
            .into_iter()
            .map(|m| (Hash::try_from(m.hash.clone()).unwrap_or_default(), m))
            .collect::<std::collections::HashMap<_, _>>();

        for (original_idx, req_hash) in request.hashes.iter().enumerate() {
            if let Some(acc_model) = model_map.remove(req_hash) {
                // Use remove to ensure each model is processed once
                let tree_pubkey =
                    SerializablePubkey::try_from_slice(&acc_model.tree).map_err(|_| {
                        PhotonApiError::UnexpectedError("Invalid nullifier tree".to_string())
                    })?;

                let tree_info = TreeInfo::get(&tree_pubkey.to_string())
                    .ok_or_else(|| {
                        PhotonApiError::UnexpectedError(format!(
                            "TreeInfo not found for tree {}",
                            tree_pubkey.to_string()
                        ))
                    })?
                    .clone();

                if acc_model.in_output_queue {
                    accounts_for_prove_by_index_inputs[original_idx] = Some(AccountProofInputs {
                        hash: Hash::new(acc_model.hash.as_slice())?.to_string(),
                        root: "".to_string(),
                        root_index: None.into(), // prove_by_index = true
                        leaf_index: acc_model.leaf_index as u64,
                        merkle_context: MerkleContextV2 {
                            tree_type: tree_info.tree_type as u16,
                            tree: SerializablePubkey::try_from_slice(&acc_model.tree).map_err(
                                |_| {
                                    PhotonApiError::UnexpectedError(
                                        "Invalid nullifier tree".to_string(),
                                    )
                                },
                            )?,
                            queue: SerializablePubkey::try_from_slice(&acc_model.queue).map_err(
                                |_| {
                                    PhotonApiError::UnexpectedError(
                                        "Invalid nullifier queue".to_string(),
                                    )
                                },
                            )?,
                            cpi_context: None,
                            next_tree_context: None,
                        },
                    });
                } else {
                    hashes_needing_full_proof.push(req_hash.clone());
                    original_indices_for_full_proof_hashes.push(original_idx);
                }
            } else {
                tx.rollback().await?;
                return Err(PhotonApiError::ValidationError(format!(
                    "Requested account hash {} not found or is spent.",
                    req_hash
                )));
            }
        }
    }

    let mut addresses_for_prove_by_index_from_queue: Vec<AddressProofInputs> = Vec::new();
    let mut new_address_proofs_for_prover_input: Vec<MerkleContextWithNewAddressProof> = Vec::new();

    if !request.new_addresses_with_trees.is_empty() {
        let address_proof_type_results = get_multiple_new_address_proofs_helper(
            &tx,
            request.new_addresses_with_trees.clone(),
            true,
        )
        .await?;

        for proof_type_result in address_proof_type_results {
            match proof_type_result {
                AddressProof::InQueue(queued_info) => {
                    let tree_info = TreeInfo::get(&queued_info.tree.to_string())
                        .ok_or_else(|| {
                            PhotonApiError::UnexpectedError(format!(
                                "TreeInfo not found for tree {}",
                                queued_info.tree
                            ))
                        })?
                        .clone();

                    addresses_for_prove_by_index_from_queue.push(AddressProofInputs {
                        address: queued_info.address.to_string(),
                        root: "".to_string(),
                        root_index: None.into(), // prove_by_index = true
                        merkle_context: MerkleContextV2 {
                            tree_type: queued_info.tree_type,
                            tree: queued_info.tree,
                            queue: SerializablePubkey::from(tree_info.queue),
                            cpi_context: None,
                            next_tree_context: None,
                        },
                    });
                }
                AddressProof::NonInclusion(non_inclusion_proof) => {
                    new_address_proofs_for_prover_input.push(non_inclusion_proof);
                }
            }
        }
    }

    let db_account_merkle_proofs_for_prover = if !hashes_needing_full_proof.is_empty() {
        get_multiple_compressed_leaf_proofs(&tx, hashes_needing_full_proof).await?
    } else {
        Vec::new()
    };

    tx.commit().await?;

    let mut v2_accounts_from_prover_results: Vec<AccountProofInputs> = Vec::new();
    let mut v2_addresses_from_prover_results: Vec<AddressProofInputs> = Vec::new();
    let mut resulting_compressed_proof: Option<CompressedProof> = None;

    // Only call prover if there are items needing full proofs
    if !db_account_merkle_proofs_for_prover.is_empty()
        || !new_address_proofs_for_prover_input.is_empty()
    {
        let internal_result = generate_proof(
            db_account_merkle_proofs_for_prover,
            new_address_proofs_for_prover_input,
            prover_url,
        )
        .await?;

        resulting_compressed_proof = Some(internal_result.compressed_proof);

        for detail in internal_result.account_proof_details {
            v2_accounts_from_prover_results.push(AccountProofInputs {
                hash: detail.hash,
                root: detail.root,
                root_index: Some(detail.root_index_mod_queue).into(),
                leaf_index: detail.leaf_index as u64,
                merkle_context: MerkleContextV2 {
                    tree_type: detail.tree_info.tree_type as u16,
                    tree: SerializablePubkey::from(detail.tree_info.tree),
                    queue: SerializablePubkey::from(detail.tree_info.queue),
                    cpi_context: None,
                    next_tree_context: None,
                },
            });
        }

        for detail in internal_result.address_proof_details {
            v2_addresses_from_prover_results.push(AddressProofInputs {
                address: detail.address,
                root: detail.root,
                root_index: Some(detail.root_index_mod_queue).into(),
                merkle_context: MerkleContextV2 {
                    tree_type: detail.tree_info.tree_type as u16,
                    tree: SerializablePubkey::from(detail.tree_info.tree),
                    queue: SerializablePubkey::from(detail.tree_info.queue),
                    cpi_context: None,
                    next_tree_context: None,
                },
            });
        }
    }

    for (i, original_idx) in original_indices_for_full_proof_hashes.iter().enumerate() {
        if i < v2_accounts_from_prover_results.len() {
            accounts_for_prove_by_index_inputs[*original_idx] =
                Some(v2_accounts_from_prover_results[i].clone());
        } else {
            return Err(PhotonApiError::UnexpectedError(format!(
                "Mismatch in prover results for account hashes. Expected result for original index {}", original_idx
            )));
        }
    }
    let final_accounts_list: Vec<AccountProofInputs> = accounts_for_prove_by_index_inputs
        .into_iter()
        .filter_map(|opt| opt)
        .collect();

    let final_addresses_list = addresses_for_prove_by_index_from_queue
        .into_iter()
        .chain(v2_addresses_from_prover_results.into_iter())
        .collect();

    Ok(GetValidityProofResponseV2 {
        value: CompressedProofWithContextV2 {
            compressed_proof: resulting_compressed_proof,
            accounts: final_accounts_list,
            addresses: final_addresses_list,
        },
        context: v2_context,
    })
}
