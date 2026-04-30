use function_name::named;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use light_compressed_account::TreeType;
use num_bigint::BigUint;
use photon_indexer::common::typedefs::serializable_pubkey::SerializablePubkey;
use photon_indexer::dao::generated::{
    accounts, blocks, indexed_trees, shielded_utxo_events, shielded_utxo_outputs, state_trees,
    tree_metadata, zone_configs,
};
use photon_indexer::ingester::parser::{
    parse_transaction,
    shielded_pool_test_fixture::{
        fixture_leaf_index_base, fixture_tree_sequence, fixture_utxo_tree, FixtureBuilder,
        FixtureOwnerSpec,
    },
    TreeResolver,
};
use photon_indexer::zone_rpc::api::{
    FetchDecryptedUtxosRequest, FetchProofInputsRequest, FetchProofInputsResponse,
    FetchProofsRequest, FetchUtxosRequest, GetProofJobRequest, GetRelayerJobRequest,
    GetZoneInfoRequest, SignedZoneIntent, SubmitIntentRequest, ZoneJobStatus, ZoneRpcApi,
};
use photon_indexer::zone_rpc::plaintext_projection::{
    ZonePlaintextProjector, ZoneRpcProjectionConfig,
};
use photon_indexer::zone_rpc::private_api::ZoneDecryptedUtxoView;
use photon_indexer::zone_rpc::private_api::{ZoneQueryAuthorization, ZoneRpcPrivateApi};
use photon_indexer::zone_rpc::private_db::{migrate_zone_private_db, SqlZonePrivateStore};
use photon_indexer::zone_rpc::prover_client::{
    ProverProofClient, ProverProofMode, ProverProofRequest,
};
use photon_indexer::zone_rpc::workers::{
    DecryptOutputsRequest, Decryptor, EncryptedUtxoInput, LocalPassthroughDecryptor,
};
use sea_orm::{ColumnTrait, Database, EntityTrait, PaginatorTrait, QueryFilter, Set};
use serde::Deserialize;
use serde_json::json;
use serial_test::serial;
use solana_signature::Signature;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::utils::*;

const FIXTURE_NULLIFIER_TREE: [u8; 32] = [0xCD; 32];
const FIXTURE_SPEND_NULLIFIER: [u8; 32] = [0x10; 32];
const FIXTURE_NULLIFIER_LOW_VALUE: [u8; 32] = [0x01; 32];
const FIXTURE_NULLIFIER_NEXT_VALUE: [u8; 32] = [0x20; 32];
const FIXTURE_NULLIFIER_ROOT_SEQUENCE: u64 = 11;
const FIXTURE_TREE_HEIGHT: i32 = 40;
const FIXTURE_ROOT_HISTORY_CAPACITY: i64 = 64;
const FIXTURE_NULLIFIER_ROOT: [u8; 32] = [0x92; 32];

#[derive(Debug, Deserialize)]
struct MaspLocalDevProofRequests {
    utxo: serde_json::Value,
    tree: serde_json::Value,
}

#[named]
#[tokio::test]
#[serial]
async fn test_shielded_pool_dummy_event_to_zone_rpc_wiring_sqlite() {
    let name = trim_test_name(function_name!());
    let setup = setup_with_options(
        name.to_string(),
        TestSetupOptions {
            network: Network::Localnet,
            db_backend: DatabaseBackend::Sqlite,
        },
    )
    .await;

    let owner = FixtureOwnerSpec {
        owner_pubkey: [0xAA; 32],
        token_mint: [0xBB; 32],
        spl_amount: 1_000_000,
        sol_amount: 42,
        blinding: [0xCC; 32],
    };
    let fixture = FixtureBuilder::proofless_shield_one_output(Signature::default(), owner).build();
    let zone_config_hash = fixture
        .event
        .zone_config_hash
        .expect("fixture must be zoned");
    let output = &fixture.event.outputs[0];

    seed_local_fixture_tree_metadata(setup.db_conn.as_ref()).await;
    let mut resolver = TreeResolver::new(setup.client.as_ref());
    let state_update = parse_transaction(
        setup.db_conn.as_ref(),
        &fixture.transaction_info,
        100,
        &mut resolver,
    )
    .await
    .expect("dummy shielded event should parse through Photon transaction parser");

    assert_eq!(state_update.shielded_tx_events.len(), 1);
    assert_eq!(state_update.shielded_outputs.len(), 1);
    assert_eq!(state_update.shielded_outputs[0].utxo_hash, output.utxo_hash);
    assert_eq!(state_update.shielded_outputs[0].compressed_output_index, 0);
    assert_eq!(
        state_update.shielded_outputs[0].leaf_index,
        fixture_leaf_index_base() as u64
    );
    assert_eq!(
        state_update.shielded_outputs[0].tree_sequence,
        fixture_tree_sequence()
    );

    blocks::Entity::insert(blocks::ActiveModel {
        slot: sea_orm::Set(100),
        parent_slot: sea_orm::Set(99),
        parent_blockhash: sea_orm::Set(vec![0u8; 32]),
        blockhash: sea_orm::Set(vec![1u8; 32]),
        block_height: sea_orm::Set(100),
        block_time: sea_orm::Set(0),
    })
    .exec(setup.db_conn.as_ref())
    .await
    .expect("synthetic shielded transaction slot must have block metadata");

    persist_state_update_using_connection(setup.db_conn.as_ref(), state_update.clone())
        .await
        .expect("first shielded state persist should succeed");
    persist_state_update_using_connection(setup.db_conn.as_ref(), state_update.clone())
        .await
        .expect("re-indexing the same shielded event should be idempotent");
    seed_local_nullifier_context(setup.db_conn.as_ref()).await;

    let persisted_account = accounts::Entity::find_by_id(
        state_update.shielded_outputs[0]
            .compressed_account_hash
            .to_vec(),
    )
    .one(setup.db_conn.as_ref())
    .await
    .expect("persisted compressed account query should succeed")
    .expect("batch append fixture should persist the compressed account row");
    assert!(!persisted_account.in_output_queue);
    assert_eq!(
        persisted_account.leaf_index,
        fixture_leaf_index_base() as i64
    );
    assert_eq!(persisted_account.tree, fixture_utxo_tree().to_vec());

    let persisted_leaf = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(fixture_utxo_tree().to_vec()))
        .filter(state_trees::Column::LeafIdx.eq(Some(fixture_leaf_index_base() as i64)))
        .filter(state_trees::Column::Level.eq(0))
        .one(setup.db_conn.as_ref())
        .await
        .expect("persisted state-tree leaf query should succeed")
        .expect("batch append fixture should persist the UTXO leaf");
    assert_eq!(
        persisted_leaf.hash,
        state_update.shielded_outputs[0]
            .compressed_account_hash
            .to_vec()
    );
    assert_eq!(persisted_leaf.seq, Some(fixture_tree_sequence() as i64));

    let persisted_root = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(fixture_utxo_tree().to_vec()))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .one(setup.db_conn.as_ref())
        .await
        .expect("persisted state-tree root query should succeed")
        .expect("batch append fixture should persist a UTXO root");
    assert_eq!(persisted_root.seq, Some(fixture_tree_sequence() as i64));

    assert_eq!(
        shielded_utxo_events::Entity::find()
            .count(setup.db_conn.as_ref())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        shielded_utxo_outputs::Entity::find()
            .count(setup.db_conn.as_ref())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        zone_configs::Entity::find()
            .count(setup.db_conn.as_ref())
            .await
            .unwrap(),
        1
    );

    let private_db = Database::connect("sqlite::memory:")
        .await
        .expect("private Zone RPC sqlite db should open");
    migrate_zone_private_db(&private_db)
        .await
        .expect("private Zone RPC schema should migrate");
    let private_store = SqlZonePrivateStore::new(private_db);

    let projector = ZonePlaintextProjector::new(ZoneRpcProjectionConfig {
        zone_config_hash,
        allow_fixture_plaintext: true,
    });
    let private_rows = projector
        .project_fixture_sidecar(&state_update, &fixture.sidecar)
        .expect("Zone RPC should project fixture plaintext after hash verification");
    assert_eq!(private_rows.len(), 1);

    let event = &state_update.shielded_tx_events[0];
    let encrypted_inputs = state_update
        .shielded_outputs
        .iter()
        .map(|output| EncryptedUtxoInput::from_records(event, output))
        .collect::<Result<Vec<_>, _>>()
        .expect("public encrypted outputs should bind to their tx event");
    let decryptor = LocalPassthroughDecryptor::new(private_rows)
        .expect("local decryptor should load hash-verified fixture plaintext");
    let decrypted_rows = decryptor
        .decrypt_outputs(DecryptOutputsRequest {
            zone_config_hash,
            outputs: encrypted_inputs,
        })
        .await
        .expect("Zone RPC decryptor should return rows bound to public outputs")
        .decrypted_outputs;
    assert_eq!(decrypted_rows.len(), 1);

    let owner_hash = fixture.sidecar.payloads[0].owner_hash;
    private_store
        .upsert_many(decrypted_rows.clone())
        .await
        .expect("Zone private store should accept projected rows");
    private_store
        .upsert_many(decrypted_rows)
        .await
        .expect("Zone private store should be idempotent");

    let private_api = ZoneRpcPrivateApi::new_unchecked_for_local_testing(private_store);
    let prover_url = spawn_local_prover_stub().await;
    let zone_rpc = ZoneRpcApi::with_proof_client(
        setup.db_conn.clone(),
        private_api,
        ProverProofClient::new(prover_url, None),
    );

    let public_by_hash = zone_rpc
        .fetch_utxos(FetchUtxosRequest {
            utxo_hash: Some(hex_0x(&output.utxo_hash)),
            ..FetchUtxosRequest::default()
        })
        .await
        .expect("Zone RPC fetch_utxos by hash should succeed");
    assert_eq!(public_by_hash.items.len(), 1);
    let public_record = &public_by_hash.items[0];

    assert_eq!(public_record.utxo_hash, hex_0x(&output.utxo_hash));
    assert_eq!(public_record.compressed_output_index, 0);
    assert_eq!(public_record.leaf_index, fixture_leaf_index_base() as u64);
    assert_eq!(public_record.sequence_number, fixture_tree_sequence());
    assert_eq!(public_record.encrypted_utxo, hex_0x(&output.encrypted_utxo));
    assert_eq!(
        public_record.event.operation_commitment,
        hex_0x(&fixture.event.operation_commitment)
    );
    assert_eq!(
        public_record.event.zone_config_hash,
        Some(hex_0x(&zone_config_hash))
    );

    let public_json = serde_json::to_string(public_record).unwrap();
    assert!(!public_json.contains("ownerPubkey"));
    assert!(!public_json.contains("blinding"));
    assert!(!public_json.contains("1000000"));

    let by_zone = zone_rpc
        .fetch_utxos(FetchUtxosRequest {
            zone_config_hash: Some(hex_0x(&zone_config_hash)),
            limit: Some(10),
            ..FetchUtxosRequest::default()
        })
        .await
        .expect("Zone RPC fetch_utxos by zone should succeed");
    assert_eq!(by_zone.items.len(), 1);
    assert_eq!(by_zone.items[0].utxo_hash, hex_0x(&output.utxo_hash));

    let zone_info = zone_rpc
        .get_zone_info(GetZoneInfoRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
        })
        .await
        .expect("Zone RPC get_zone_info should succeed")
        .value
        .expect("Zone info should exist after event persistence");
    assert_eq!(zone_info.zone_config_hash, hex_0x(&zone_config_hash));
    assert_eq!(zone_info.first_seen_slot, 100);
    assert_eq!(zone_info.last_seen_slot, 100);

    let decrypted = zone_rpc
        .fetch_decrypted_utxos(FetchDecryptedUtxosRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
            owner_hash: Some(hex_0x(&owner_hash)),
            owner_pubkey: None,
            authorization: test_authorization(),
            include_spent: None,
            limit: Some(10),
        })
        .await
        .expect("private Zone RPC should fetch by owner hash")
        .items;
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted[0].utxo_hash, hex_0x(&output.utxo_hash));
    assert_eq!(decrypted[0].spl_amount, "1000000");
    assert_eq!(decrypted[0].sol_amount, "42");

    let proof_inputs = zone_rpc
        .fetch_proof_inputs(FetchProofInputsRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
            input_utxo_hashes: vec![hex_0x(&output.utxo_hash)],
            spend_nullifiers: vec![hex_0x(&FIXTURE_SPEND_NULLIFIER)],
            nullifier_tree: Some(SerializablePubkey::from(FIXTURE_NULLIFIER_TREE)),
            utxo_root_sequence: Some(fixture_tree_sequence()),
            nullifier_root_sequence: Some(FIXTURE_NULLIFIER_ROOT_SEQUENCE),
            authorization: test_authorization(),
        })
        .await
        .expect("Zone RPC should return Light-bound proof input context");
    assert_eq!(proof_inputs.inputs.len(), 1);
    assert_eq!(proof_inputs.inputs[0].utxo_hash, hex_0x(&output.utxo_hash));
    assert_eq!(proof_inputs.inputs[0].leaf_index, public_record.leaf_index);
    assert_eq!(
        proof_inputs.inputs[0].tree_sequence,
        public_record.sequence_number
    );
    assert_eq!(proof_inputs.inputs[0].utxo_tree, public_record.utxo_tree);
    assert_eq!(
        proof_inputs.inputs[0].compressed_account_hash,
        public_record.compressed_account_hash
    );
    assert_eq!(
        proof_inputs.inputs[0].compressed_output_index,
        public_record.compressed_output_index
    );
    assert_eq!(
        proof_inputs.inputs[0].encrypted_utxo,
        public_record.encrypted_utxo
    );
    assert_eq!(proof_inputs.inputs[0].slot, public_record.slot);
    assert_eq!(
        proof_inputs.inputs[0].event_index,
        public_record.event_index
    );
    assert_eq!(
        proof_inputs.inputs[0].tx_signature.0.to_string(),
        public_record.signature.0.to_string()
    );
    assert_eq!(
        proof_inputs
            .root_context_status
            .utxo_inclusion_proofs_available,
        proof_inputs.inputs[0].compressed_account_proof.is_some()
    );
    assert!(proof_inputs.root_context_status.nullifier_context_available);
    assert!(
        proof_inputs.root_context_status.is_available,
        "root context unavailable: {:?}",
        proof_inputs.root_context_status.unavailable_reasons
    );
    assert!(proof_inputs
        .root_context_status
        .unavailable_reasons
        .is_empty());
    assert_eq!(
        proof_inputs.utxo_root_sequence,
        Some(fixture_tree_sequence())
    );
    assert_eq!(
        proof_inputs.nullifier_root_sequence,
        Some(FIXTURE_NULLIFIER_ROOT_SEQUENCE)
    );
    let compressed_proof = proof_inputs.inputs[0]
        .compressed_account_proof
        .as_ref()
        .expect("persisted batch append fixture should produce compressed account proof");
    let root_context = proof_inputs
        .root_context
        .as_ref()
        .expect("local fixture should produce full MASP root context");
    assert_eq!(root_context.utxo_tree_id, public_record.utxo_tree);
    assert_eq!(root_context.utxo_root, compressed_proof.root);
    assert_eq!(
        root_context.utxo_root_index,
        fixture_tree_sequence() % FIXTURE_ROOT_HISTORY_CAPACITY as u64
    );
    assert_eq!(root_context.utxo_root_sequence, fixture_tree_sequence());
    assert_eq!(
        root_context.nullifier_tree_id,
        hex_0x(&FIXTURE_NULLIFIER_TREE)
    );
    assert_eq!(root_context.nullifier_root, hex_0x(&FIXTURE_NULLIFIER_ROOT));
    assert_eq!(
        root_context.nullifier_root_index,
        FIXTURE_NULLIFIER_ROOT_SEQUENCE % FIXTURE_ROOT_HISTORY_CAPACITY as u64
    );
    assert_eq!(
        root_context.nullifier_root_sequence,
        FIXTURE_NULLIFIER_ROOT_SEQUENCE
    );
    assert_eq!(
        proof_inputs.root_context_status.required_utxo_trees[0].utxo_tree,
        public_record.utxo_tree
    );
    assert_eq!(
        proof_inputs.root_context_status.required_utxo_trees[0].max_tree_sequence,
        public_record.sequence_number
    );
    assert_eq!(compressed_proof.hash, public_record.compressed_account_hash);
    assert_eq!(compressed_proof.leaf_index as u64, public_record.leaf_index);
    assert_eq!(compressed_proof.root_sequence, fixture_tree_sequence());
    assert_eq!(
        compressed_proof.root_index,
        Some(fixture_tree_sequence() % FIXTURE_ROOT_HISTORY_CAPACITY as u64)
    );
    let nullifier_proof = proof_inputs.inputs[0]
        .nullifier_non_inclusion_proof
        .as_ref()
        .expect("seeded local fixture should produce nullifier non-inclusion proof");
    assert_eq!(nullifier_proof.nullifier, hex_0x(&FIXTURE_SPEND_NULLIFIER));
    assert_eq!(
        nullifier_proof.nullifier_tree,
        SerializablePubkey::from(FIXTURE_NULLIFIER_TREE)
    );
    assert_eq!(nullifier_proof.root, hex_0x(&FIXTURE_NULLIFIER_ROOT));
    assert_eq!(
        nullifier_proof.root_sequence,
        FIXTURE_NULLIFIER_ROOT_SEQUENCE
    );
    assert_eq!(
        nullifier_proof.root_index,
        FIXTURE_NULLIFIER_ROOT_SEQUENCE % FIXTURE_ROOT_HISTORY_CAPACITY as u64
    );
    assert_eq!(
        nullifier_proof.low_value,
        hex_0x(&FIXTURE_NULLIFIER_LOW_VALUE)
    );
    assert_eq!(
        nullifier_proof.next_value,
        hex_0x(&FIXTURE_NULLIFIER_NEXT_VALUE)
    );

    let proof_requests = local_stub_masp_proof_requests(&proof_inputs, &decrypted);
    let tree_payload: serde_json::Value =
        serde_json::from_str(&proof_requests[1].payload).expect("tree payload should decode");
    assert_eq!(
        tree_payload["rootContext"],
        root_context_json(&proof_inputs)
    );
    assert_eq!(
        tree_payload["localWitness"]["statePath"][0]
            .as_array()
            .expect("state path should be an array")
            .len(),
        proof_inputs.inputs[0]
            .compressed_account_proof
            .as_ref()
            .unwrap()
            .proof
            .len()
    );
    assert_eq!(
        tree_payload["localWitness"]["nfLowPath"][0]
            .as_array()
            .expect("nullifier path should be an array")
            .len(),
        proof_inputs.inputs[0]
            .nullifier_non_inclusion_proof
            .as_ref()
            .unwrap()
            .proof
            .len()
    );

    let proof_job = zone_rpc
        .fetch_proofs(FetchProofsRequest {
            intent: test_intent(),
            proof_requests,
            prover_mode: Some(ProverProofMode::Sync),
        })
        .await
        .expect("local/dev Zone RPC should submit proof jobs to prover-server");
    assert_eq!(proof_job.proof_jobs.len(), 2);
    assert!(proof_job
        .proof_jobs
        .iter()
        .all(|job| job.status == ZoneJobStatus::Succeeded));
    let proof_job_status = zone_rpc
        .get_proof_job(GetProofJobRequest {
            proof_job_id: proof_job.proof_job_id,
        })
        .await
        .expect("queued proof job should be readable");
    assert_eq!(proof_job_status.status, ZoneJobStatus::Succeeded);
    assert!(proof_job_status
        .result
        .as_deref()
        .unwrap()
        .contains("local-real-prover-boundary-proof"));

    let relayer_job = zone_rpc
        .submit_intent(SubmitIntentRequest {
            intent: test_intent(),
        })
        .await
        .expect("local/dev Zone RPC should queue relayer jobs");
    let relayer_job_status = zone_rpc
        .get_relayer_job(GetRelayerJobRequest {
            relayer_job_id: relayer_job.relayer_job_id,
        })
        .await
        .expect("queued relayer job should be readable");
    assert_eq!(relayer_job_status.status, ZoneJobStatus::Queued);
    assert!(relayer_job_status.result.is_none());

    assert!(zone_rpc
        .fetch_decrypted_utxos(FetchDecryptedUtxosRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
            owner_hash: Some(hex_0x(&[0x11; 32])),
            owner_pubkey: None,
            authorization: test_authorization(),
            include_spent: None,
            limit: Some(10),
        })
        .await
        .unwrap()
        .items
        .is_empty());
    assert!(zone_rpc
        .fetch_decrypted_utxos(FetchDecryptedUtxosRequest {
            zone_config_hash: hex_0x(&[0x22; 32]),
            owner_hash: Some(hex_0x(&owner_hash)),
            owner_pubkey: None,
            authorization: test_authorization(),
            include_spent: None,
            limit: Some(10),
        })
        .await
        .unwrap()
        .items
        .is_empty());
}

async fn seed_local_fixture_tree_metadata(conn: &sea_orm::DatabaseConnection) {
    tree_metadata::Entity::insert(tree_metadata::ActiveModel {
        tree_pubkey: Set(fixture_utxo_tree().to_vec()),
        queue_pubkey: Set(fixture_utxo_tree().to_vec()),
        tree_type: Set(tree_type_id(TreeType::StateV2)),
        height: Set(FIXTURE_TREE_HEIGHT),
        root_history_capacity: Set(FIXTURE_ROOT_HISTORY_CAPACITY),
        sequence_number: Set(0),
        next_index: Set(0),
        last_synced_slot: Set(100),
    })
    .exec(conn)
    .await
    .expect("local fixture should seed UTXO tree metadata");
}

async fn seed_local_nullifier_context(conn: &sea_orm::DatabaseConnection) {
    tree_metadata::Entity::insert(tree_metadata::ActiveModel {
        tree_pubkey: Set(FIXTURE_NULLIFIER_TREE.to_vec()),
        queue_pubkey: Set([0xD0; 32].to_vec()),
        tree_type: Set(tree_type_id(TreeType::AddressV2)),
        height: Set(FIXTURE_TREE_HEIGHT),
        root_history_capacity: Set(FIXTURE_ROOT_HISTORY_CAPACITY),
        sequence_number: Set(FIXTURE_NULLIFIER_ROOT_SEQUENCE as i64),
        next_index: Set(2),
        last_synced_slot: Set(100),
    })
    .exec(conn)
    .await
    .expect("local fixture should seed nullifier tree metadata");

    state_trees::Entity::insert_many(vec![state_trees::ActiveModel {
        tree: Set(FIXTURE_NULLIFIER_TREE.to_vec()),
        node_idx: Set(1),
        leaf_idx: Set(None),
        level: Set(FIXTURE_TREE_HEIGHT as i64),
        hash: Set(FIXTURE_NULLIFIER_ROOT.to_vec()),
        seq: Set(Some(FIXTURE_NULLIFIER_ROOT_SEQUENCE as i64)),
    }])
    .exec(conn)
    .await
    .expect("local fixture should seed nullifier proof root");

    indexed_trees::Entity::insert(indexed_trees::ActiveModel {
        tree: Set(FIXTURE_NULLIFIER_TREE.to_vec()),
        leaf_index: Set(0),
        value: Set(FIXTURE_NULLIFIER_LOW_VALUE.to_vec()),
        next_index: Set(1),
        next_value: Set(FIXTURE_NULLIFIER_NEXT_VALUE.to_vec()),
        seq: Set(Some(FIXTURE_NULLIFIER_ROOT_SEQUENCE as i64)),
    })
    .exec(conn)
    .await
    .expect("local fixture should seed indexed nullifier range");
}

fn tree_type_id(tree_type: TreeType) -> i32 {
    match tree_type {
        TreeType::StateV1 => 1,
        TreeType::AddressV1 => 2,
        TreeType::StateV2 => 3,
        TreeType::AddressV2 => 4,
        TreeType::Unknown => panic!("local proof fixture must not use unknown tree type"),
    }
}

fn local_stub_masp_proof_requests(
    proof_inputs: &FetchProofInputsResponse,
    decrypted_inputs: &[ZoneDecryptedUtxoView],
) -> Vec<ProverProofRequest> {
    vec![
        proof_request_from_payload(
            "masp-utxo",
            masp_utxo_payload_from_zone_inputs(proof_inputs, decrypted_inputs),
        ),
        proof_request_from_payload(
            "masp-tree",
            masp_tree_payload_from_zone_inputs(proof_inputs),
        ),
    ]
}

fn masp_proof_requests_from_generated_templates(
    proof_inputs: &FetchProofInputsResponse,
    fixtures: MaspLocalDevProofRequests,
) -> Vec<ProverProofRequest> {
    vec![
        proof_request_from_payload(
            "masp-utxo",
            patch_masp_payload_from_zone_inputs("masp-utxo", fixtures.utxo, proof_inputs),
        ),
        proof_request_from_payload(
            "masp-tree",
            patch_masp_payload_from_zone_inputs("masp-tree", fixtures.tree, proof_inputs),
        ),
    ]
}

fn masp_tree_payload_from_zone_inputs(
    proof_inputs: &FetchProofInputsResponse,
) -> serde_json::Value {
    let inputs = proof_inputs.inputs.as_slice();
    assert!(!inputs.is_empty(), "MASP tree request requires inputs");

    // Current MASP names this value `inCommit`. In the Light compressed-account
    // path this is the state-tree leaf hash; production MASP must also bind it
    // to the private UTXO commitment used by the UTXO proof.
    let in_commit = inputs
        .iter()
        .map(|input| decimal_from_hex_0x(&input.compressed_account_hash))
        .collect::<Vec<_>>();
    let state_path = inputs
        .iter()
        .map(|input| {
            input
                .compressed_account_proof
                .as_ref()
                .expect("MASP tree request requires compressed account proofs")
                .proof
                .iter()
                .map(|node| decimal_from_hex_0x(node))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let state_dirs = inputs
        .iter()
        .map(|input| {
            input
                .compressed_account_proof
                .as_ref()
                .expect("MASP tree request requires compressed account proofs")
                .path_directions
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let nf_low_value = inputs
        .iter()
        .map(|input| {
            decimal_from_hex_0x(
                &input
                    .nullifier_non_inclusion_proof
                    .as_ref()
                    .expect("MASP tree request requires nullifier proofs")
                    .low_value,
            )
        })
        .collect::<Vec<_>>();
    let nf_next_value = inputs
        .iter()
        .map(|input| {
            decimal_from_hex_0x(
                &input
                    .nullifier_non_inclusion_proof
                    .as_ref()
                    .expect("MASP tree request requires nullifier proofs")
                    .next_value,
            )
        })
        .collect::<Vec<_>>();
    let nf_low_path = inputs
        .iter()
        .map(|input| {
            input
                .nullifier_non_inclusion_proof
                .as_ref()
                .expect("MASP tree request requires nullifier proofs")
                .proof
                .iter()
                .map(|node| decimal_from_hex_0x(node))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let nf_low_dirs = inputs
        .iter()
        .map(|input| {
            input
                .nullifier_non_inclusion_proof
                .as_ref()
                .expect("MASP tree request requires nullifier proofs")
                .path_directions
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let state_roots = inputs
        .iter()
        .map(|input| {
            decimal_from_hex_0x(
                &input
                    .compressed_account_proof
                    .as_ref()
                    .expect("MASP tree request requires compressed account proofs")
                    .root,
            )
        })
        .collect::<Vec<_>>();
    let nullifier_roots = inputs
        .iter()
        .map(|input| {
            decimal_from_hex_0x(
                &input
                    .nullifier_non_inclusion_proof
                    .as_ref()
                    .expect("MASP tree request requires nullifier proofs")
                    .root,
            )
        })
        .collect::<Vec<_>>();
    let nullifiers = inputs
        .iter()
        .map(|input| {
            decimal_from_hex_0x(
                input
                    .spend_nullifier
                    .as_deref()
                    .expect("MASP tree request requires spend nullifiers"),
            )
        })
        .collect::<Vec<_>>();

    json!({
        "circuitType": "masp-tree",
        "nInputs": inputs.len(),
        "nOutputs": 0,
        "rootContext": root_context_json(proof_inputs),
        "operationCommitment": operation_commitment_from_inputs(proof_inputs),
        "publicInputsHash": "1",
        "localWitness": {
            "inCommit": in_commit,
            "statePath": state_path,
            "stateDirs": state_dirs,
            "domainDns": vec!["1".to_string(); inputs.len()],
            "nfLowValue": nf_low_value,
            "nfNextValue": nf_next_value,
            "nfLowPath": nf_low_path,
            "nfLowDirs": nf_low_dirs,
            "stateRoots": state_roots,
            "nullifierRoots": nullifier_roots,
            "nullifiers": nullifiers,
        }
    })
}

fn masp_utxo_payload_from_zone_inputs(
    proof_inputs: &FetchProofInputsResponse,
    decrypted_inputs: &[ZoneDecryptedUtxoView],
) -> serde_json::Value {
    let ordered_inputs = decrypted_inputs_for_proof_order(proof_inputs, decrypted_inputs);
    let nullifiers = proof_inputs
        .inputs
        .iter()
        .map(|input| {
            decimal_from_hex_0x(
                input
                    .spend_nullifier
                    .as_deref()
                    .expect("MASP UTXO request requires spend nullifiers"),
            )
        })
        .collect::<Vec<_>>();
    let output_owner = ordered_inputs
        .first()
        .expect("MASP UTXO request requires at least one decrypted input")
        .owner_pubkey
        .clone();
    let output_data_hash = ordered_inputs
        .first()
        .expect("MASP UTXO request requires at least one decrypted input")
        .data_hash
        .clone();

    json!({
        "circuitType": "masp-utxo",
        "nInputs": ordered_inputs.len(),
        "nOutputs": 1,
        "rootContext": root_context_json(proof_inputs),
        "operationCommitment": operation_commitment_from_inputs(proof_inputs),
        "publicInputsHash": "1",
        "localWitness": {
            "inOwner": ordered_inputs.iter().map(|input| decimal_from_hex_0x(&input.owner_pubkey)).collect::<Vec<_>>(),
            "inSpl": ordered_inputs.iter().map(|input| input.spl_amount.clone()).collect::<Vec<_>>(),
            "inSol": ordered_inputs.iter().map(|input| input.sol_amount.clone()).collect::<Vec<_>>(),
            "inBlinding": vec!["0".to_string(); ordered_inputs.len()],
            "inDataHash": ordered_inputs.iter().map(|input| decimal_from_hex_0x(&input.data_hash)).collect::<Vec<_>>(),
            "inSeed": vec!["0".to_string(); ordered_inputs.len()],
            "inProgramId": vec!["0".to_string(); ordered_inputs.len()],
            "inLeafIndex": proof_inputs.inputs.iter().map(|input| input.leaf_index.to_string()).collect::<Vec<_>>(),
            "nullifierSecret": "1",
            "outOwner": vec![decimal_from_hex_0x(&output_owner)],
            "outSpl": vec![sum_decimal_strings(ordered_inputs.iter().map(|input| input.spl_amount.as_str()))],
            "outSol": vec![sum_decimal_strings(ordered_inputs.iter().map(|input| input.sol_amount.as_str()))],
            "outBlinding": vec!["0"],
            "outDataHash": vec![decimal_from_hex_0x(&output_data_hash)],
            "outOwnerIsProgram": vec!["0"],
            "outOwnerProgramIndex": vec!["0"],
            "outSeed": vec!["0"],
            "txBlinding": "0",
            "pubX": ["0", "0"],
            "pubY": ["0", "0"],
            "sigR": ["0", "0"],
            "sigS": ["0", "0"],
            "nullifiers": nullifiers,
            "outputCommitments": vec!["0"],
            "txHash": "0",
            "seedsHashchain": "0",
            "programIdHashchain": "0",
            "shaTxHash": "0",
            "nullifierChain": "0",
        }
    })
}

fn decrypted_inputs_for_proof_order<'a>(
    proof_inputs: &FetchProofInputsResponse,
    decrypted_inputs: &'a [ZoneDecryptedUtxoView],
) -> Vec<&'a ZoneDecryptedUtxoView> {
    proof_inputs
        .inputs
        .iter()
        .map(|proof_input| {
            decrypted_inputs
                .iter()
                .find(|decrypted| decrypted.utxo_hash == proof_input.utxo_hash)
                .expect("MASP UTXO request requires decrypted data for every proof input")
        })
        .collect()
}

fn patch_masp_payload_from_zone_inputs(
    circuit_type: &str,
    mut payload: serde_json::Value,
    proof_inputs: &FetchProofInputsResponse,
) -> serde_json::Value {
    assert_eq!(
        payload
            .get("circuitType")
            .and_then(serde_json::Value::as_str),
        Some(circuit_type)
    );
    let object = payload
        .as_object_mut()
        .expect("generated MASP payload must be a JSON object");
    object.insert("rootContext".to_string(), root_context_json(proof_inputs));
    object.insert(
        "operationCommitment".to_string(),
        json!(operation_commitment_from_inputs(proof_inputs)),
    );
    object.insert("nInputs".to_string(), json!(proof_inputs.inputs.len()));
    payload
}

fn root_context_json(proof_inputs: &FetchProofInputsResponse) -> serde_json::Value {
    serde_json::to_value(
        proof_inputs
            .root_context
            .as_ref()
            .expect("MASP proof request requires root context"),
    )
    .expect("root context should serialize")
}

fn operation_commitment_from_inputs(proof_inputs: &FetchProofInputsResponse) -> String {
    let first = proof_inputs
        .inputs
        .first()
        .expect("MASP proof request requires inputs")
        .operation_commitment
        .clone();
    assert!(
        proof_inputs
            .inputs
            .iter()
            .all(|input| input.operation_commitment == first),
        "local/dev MASP builder currently expects one operation commitment"
    );
    first
}

fn decimal_from_hex_0x(value: &str) -> String {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.is_empty() {
        return "0".to_string();
    }
    BigUint::parse_bytes(hex.as_bytes(), 16)
        .expect("hex field should decode")
        .to_str_radix(10)
}

fn sum_decimal_strings<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values
        .map(|value| BigUint::parse_bytes(value.as_bytes(), 10).expect("decimal amount"))
        .fold(BigUint::from(0u8), |acc, value| acc + value)
        .to_str_radix(10)
}

async fn zone_rpc_fixture_with_proof_inputs(
    name: &str,
    prover_url: String,
) -> (
    ZoneRpcApi,
    FetchProofInputsResponse,
    Vec<ZoneDecryptedUtxoView>,
) {
    let setup = setup_with_options(
        name.to_string(),
        TestSetupOptions {
            network: Network::Localnet,
            db_backend: DatabaseBackend::Sqlite,
        },
    )
    .await;

    let owner = FixtureOwnerSpec {
        owner_pubkey: [0xAA; 32],
        token_mint: [0xBB; 32],
        spl_amount: 1_000_000,
        sol_amount: 42,
        blinding: [0xCC; 32],
    };
    let fixture = FixtureBuilder::proofless_shield_one_output(Signature::default(), owner).build();
    let zone_config_hash = fixture
        .event
        .zone_config_hash
        .expect("fixture must be zoned");
    let output = &fixture.event.outputs[0];

    seed_local_fixture_tree_metadata(setup.db_conn.as_ref()).await;
    let mut resolver = TreeResolver::new(setup.client.as_ref());
    let state_update = parse_transaction(
        setup.db_conn.as_ref(),
        &fixture.transaction_info,
        100,
        &mut resolver,
    )
    .await
    .expect("dummy shielded event should parse through Photon transaction parser");

    blocks::Entity::insert(blocks::ActiveModel {
        slot: Set(100),
        parent_slot: Set(99),
        parent_blockhash: Set(vec![0u8; 32]),
        blockhash: Set(vec![1u8; 32]),
        block_height: Set(100),
        block_time: Set(0),
    })
    .exec(setup.db_conn.as_ref())
    .await
    .expect("synthetic shielded transaction slot must have block metadata");

    persist_state_update_using_connection(setup.db_conn.as_ref(), state_update.clone())
        .await
        .expect("shielded state persist should succeed");
    seed_local_nullifier_context(setup.db_conn.as_ref()).await;

    let private_conn = Database::connect("sqlite::memory:")
        .await
        .expect("private Zone RPC sqlite db should open");
    migrate_zone_private_db(&private_conn)
        .await
        .expect("private Zone RPC schema should migrate");
    let private_store = SqlZonePrivateStore::new(private_conn);
    let projector = ZonePlaintextProjector::new(ZoneRpcProjectionConfig {
        zone_config_hash,
        allow_fixture_plaintext: true,
    });
    let private_rows = projector
        .project_fixture_sidecar(&state_update, &fixture.sidecar)
        .expect("Zone RPC should project fixture plaintext after hash verification");
    let event = &state_update.shielded_tx_events[0];
    let encrypted_inputs = state_update
        .shielded_outputs
        .iter()
        .map(|output| EncryptedUtxoInput::from_records(event, output))
        .collect::<Result<Vec<_>, _>>()
        .expect("public encrypted outputs should bind to their tx event");
    let decryptor = LocalPassthroughDecryptor::new(private_rows)
        .expect("local decryptor should load hash-verified fixture plaintext");
    let decrypted_rows = decryptor
        .decrypt_outputs(DecryptOutputsRequest {
            zone_config_hash,
            outputs: encrypted_inputs,
        })
        .await
        .expect("Zone RPC decryptor should return rows bound to public outputs")
        .decrypted_outputs;
    private_store
        .upsert_many(decrypted_rows)
        .await
        .expect("Zone private store should accept projected rows");

    let private_api = ZoneRpcPrivateApi::new_unchecked_for_local_testing(private_store);
    let zone_rpc = ZoneRpcApi::with_proof_client(
        setup.db_conn.clone(),
        private_api,
        ProverProofClient::new(prover_url, None),
    );

    let owner_hash = fixture.sidecar.payloads[0].owner_hash;
    let decrypted = zone_rpc
        .fetch_decrypted_utxos(FetchDecryptedUtxosRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
            owner_hash: Some(hex_0x(&owner_hash)),
            owner_pubkey: None,
            authorization: test_authorization(),
            include_spent: None,
            limit: Some(10),
        })
        .await
        .expect("private Zone RPC should fetch by owner hash")
        .items;
    let proof_inputs = zone_rpc
        .fetch_proof_inputs(FetchProofInputsRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
            input_utxo_hashes: vec![hex_0x(&output.utxo_hash)],
            spend_nullifiers: vec![hex_0x(&FIXTURE_SPEND_NULLIFIER)],
            nullifier_tree: Some(SerializablePubkey::from(FIXTURE_NULLIFIER_TREE)),
            utxo_root_sequence: Some(fixture_tree_sequence()),
            nullifier_root_sequence: Some(FIXTURE_NULLIFIER_ROOT_SEQUENCE),
            authorization: test_authorization(),
        })
        .await
        .expect("Zone RPC should return Light-bound proof input context");
    assert!(
        proof_inputs.root_context_status.is_available,
        "root context unavailable: {:?}",
        proof_inputs.root_context_status.unavailable_reasons
    );

    (zone_rpc, proof_inputs, decrypted)
}

fn generate_masp_local_dev_proof_requests() -> MaspLocalDevProofRequests {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("Photon crate should live under external/photon");
    let prover_dir = repo_root.join("prover/server");
    let go_bin = std::env::var("GO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join(".local/go/bin/go"));
    let output_path = std::env::temp_dir().join(format!(
        "light-masp-local-dev-proof-requests-{}.json",
        std::process::id()
    ));

    let status = Command::new(&go_bin)
        .arg("test")
        .arg("./prover/masp")
        .arg("-run")
        .arg("TestExportLocalDevProofRequestFixtures")
        .arg("-count=1")
        .env("MASP_FIXTURE_OUT", &output_path)
        .current_dir(&prover_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .unwrap_or_else(|err| panic!("failed to run {go_bin:?} fixture exporter: {err}"));
    assert!(status.success(), "MASP fixture exporter failed: {status}");

    let fixtures = std::fs::read_to_string(&output_path)
        .unwrap_or_else(|err| panic!("failed to read {output_path:?}: {err}"));
    let parsed = serde_json::from_str(&fixtures).expect("generated MASP fixtures should decode");
    let _ = std::fs::remove_file(output_path);
    parsed
}

#[tokio::test]
#[serial]
#[ignore = "spawns Go prover-server and generates real Groth16 proofs"]
async fn test_zone_rpc_fetch_proofs_against_real_masp_prover() {
    let prover = spawn_real_masp_prover().await;
    let fixtures = generate_masp_local_dev_proof_requests();
    let (zone_rpc, proof_inputs, _) =
        zone_rpc_fixture_with_proof_inputs("zone_rpc_real_masp_prover", prover.url.clone()).await;

    let proof_job = zone_rpc
        .fetch_proofs(FetchProofsRequest {
            intent: test_intent(),
            proof_requests: masp_proof_requests_from_generated_templates(&proof_inputs, fixtures),
            prover_mode: Some(ProverProofMode::Sync),
        })
        .await
        .expect("Zone RPC should submit real MASP proof requests to prover-server");

    assert_eq!(proof_job.proof_jobs.len(), 2);
    assert!(proof_job
        .proof_jobs
        .iter()
        .all(|job| job.status == ZoneJobStatus::Succeeded));
    assert!(proof_job.proof_jobs.iter().all(|job| job
        .result
        .as_deref()
        .is_some_and(|result| result.contains("\"ar\"") && result.contains("\"krs\""))));

    let proof_job_status = zone_rpc
        .get_proof_job(GetProofJobRequest {
            proof_job_id: proof_job.proof_job_id,
        })
        .await
        .expect("Zone RPC should store the real proof job aggregate");
    assert_eq!(proof_job_status.status, ZoneJobStatus::Succeeded);
    let result = proof_job_status.result.as_deref().unwrap();
    assert!(result.contains("masp-utxo"));
    assert!(result.contains("masp-tree"));
    assert!(result.contains("ar"));
    assert!(result.contains("krs"));
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn proof_request_from_payload(
    circuit_type: &str,
    payload: serde_json::Value,
) -> ProverProofRequest {
    assert_eq!(
        payload
            .get("circuitType")
            .and_then(serde_json::Value::as_str),
        Some(circuit_type)
    );
    ProverProofRequest {
        circuit_type: circuit_type.to_string(),
        payload: serde_json::to_string(&payload).expect("MASP fixture should encode"),
    }
}

fn test_authorization() -> ZoneQueryAuthorization {
    ZoneQueryAuthorization {
        requester: "local-test".to_string(),
        message: "local-test-query".to_string(),
        signature: "local-test-signature".to_string(),
    }
}

fn test_intent() -> SignedZoneIntent {
    SignedZoneIntent {
        intent_hash: hex_0x(&[0x44; 32]),
        intent_payload: "local-dev-intent-payload".to_string(),
        signer: "local-dev-signer".to_string(),
        signature: "local-dev-signature".to_string(),
    }
}

async fn spawn_local_prover_stub() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("local prover stub should bind to an ephemeral port");
    let addr = listener.local_addr().unwrap();
    let make_service = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(service_fn(|request: Request<Body>| async move {
            let response = match (request.method().as_str(), request.uri().path()) {
                ("POST", "/prove") => Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"proof":"local-real-prover-boundary-proof","proof_duration_ms":1}"#,
                    ))
                    .unwrap(),
                ("GET", "/prove/status") => Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"job_id":"stub-job","status":"completed","result":{"proof":"local-real-prover-boundary-proof"}}"#,
                    ))
                    .unwrap(),
                _ => Response::builder().status(404).body(Body::empty()).unwrap(),
            };
            Ok::<_, hyper::Error>(response)
        }))
    });
    let server = Server::from_tcp(listener)
        .expect("local prover stub should start from listener")
        .serve(make_service);
    tokio::spawn(server);
    format!("http://{}", addr)
}

struct ProverProcess {
    url: String,
    child: Child,
}

impl Drop for ProverProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn spawn_real_masp_prover() -> ProverProcess {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("Photon crate should live under external/photon");
    let prover_dir = repo_root.join("prover/server");
    let go_bin = std::env::var("GO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join(".local/go/bin/go"));

    let (prover_port, metrics_port) = unused_local_ports();
    let url = format!("http://127.0.0.1:{prover_port}");
    let keys_dir =
        std::env::temp_dir().join(format!("light-masp-prover-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&keys_dir).expect("test keys dir should be creatable");

    let mut child = Command::new(&go_bin)
        .arg("run")
        .arg(".")
        .arg("start")
        .arg("--prover-address")
        .arg(format!("127.0.0.1:{prover_port}"))
        .arg("--metrics-address")
        .arg(format!("127.0.0.1:{metrics_port}"))
        .arg("--circuit")
        .arg("masp")
        .arg("--keys-dir")
        .arg(keys_dir)
        .current_dir(&prover_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|err| panic!("failed to spawn {go_bin:?} in {prover_dir:?}: {err}"));

    wait_for_prover_health(&url, &mut child).await;
    ProverProcess { url, child }
}

async fn wait_for_prover_health(url: &str, child: &mut Child) {
    let client = reqwest::Client::new();
    for _ in 0..120 {
        if let Some(status) = child
            .try_wait()
            .expect("prover process status should be readable")
        {
            panic!("prover process exited before health check passed: {status}");
        }
        if let Ok(response) = client.get(format!("{url}/health")).send().await {
            if response.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("prover health check did not pass for {url}");
}

fn unused_local_ports() -> (u16, u16) {
    let prover_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral local port should bind");
    let metrics_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral local port should bind");
    let prover_port = prover_listener
        .local_addr()
        .expect("ephemeral local port should have an address")
        .port();
    let metrics_port = metrics_listener
        .local_addr()
        .expect("ephemeral local port should have an address")
        .port();
    (prover_port, metrics_port)
}
