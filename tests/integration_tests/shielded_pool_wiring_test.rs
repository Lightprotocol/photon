use ark_bn254::Fr;
use function_name::named;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use light_compressed_account::{address::derive_address, hash_to_bn254_field_size_be, TreeType};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use num_bigint::BigUint;
use photon_indexer::common::typedefs::serializable_pubkey::SerializablePubkey;
use photon_indexer::dao::generated::{
    accounts, address_queues, blocks, indexed_trees, shielded_nullifier_events, shielded_utxo_events,
    shielded_utxo_outputs, state_tree_histories, state_trees, tree_metadata, zone_configs,
};
use photon_indexer::ingester::parser::indexer_events::{BatchEvent, MerkleTreeEvent};
use photon_indexer::ingester::parser::{
    parse_transaction, SHIELDED_POOL_TEST_PROGRAM_ID,
    shielded_pool_test_fixture::{
        fixture_leaf_index_base, fixture_light_account_discriminator,
        fixture_light_account_owner_hash, fixture_masp_input_seed, fixture_masp_output_seed,
        fixture_masp_program_id, CapturedShieldedPoolFixture, FixtureBuilder, FixtureOwnerSpec,
        ProoflessAppendCaptureSnapshot, ProoflessSpendCaptureSnapshot,
    },
    state_update::StateUpdate,
    TreeResolver,
};
use photon_indexer::ingester::persist::{
    compute_parent_hash,
    indexed_merkle_tree::{compute_range_node_hash_v2, get_zeroeth_exclusion_range},
    persisted_state_tree::ZERO_BYTES,
};
use photon_indexer::zone_rpc::api::{
    FetchDecryptedUtxosRequest, FetchProofInputsRequest, FetchProofInputsResponse,
    FetchProofsRequest, FetchUtxosRequest, GetProofJobRequest, GetRelayerJobRequest,
    GetZoneInfoRequest, SignedZoneIntent, SubmitIntentRequest, ZoneJobStatus, ZoneRpcApi,
};
use photon_indexer::zone_rpc::local_masp::{
    proof_requests_from_local_dev_payloads, LocalMaspInputSecret, LocalMaspOutputSecret,
    LocalMaspWitnessSecrets, MaspLocalDevProofPayloads,
};
use photon_indexer::zone_rpc::plaintext_projection::{
    ZonePlaintextProjector, ZoneRpcProjectionConfig,
};
use photon_indexer::zone_rpc::private_api::ZoneDecryptedUtxoView;
use photon_indexer::zone_rpc::private_api::{ZoneQueryAuthorization, ZoneRpcPrivateApi};
use photon_indexer::zone_rpc::private_db::{migrate_zone_private_db, SqlZonePrivateStore};
use photon_indexer::zone_rpc::prover_client::{ProverProofClient, ProverProofMode};
use photon_indexer::zone_rpc::workers::{
    DecryptOutputsRequest, Decryptor, EncryptedUtxoInput, LocalPassthroughDecryptor,
};
use sea_orm::{ColumnTrait, Database, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set};
use serial_test::serial;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::utils::*;

const FIXTURE_NULLIFIER_ROOT_SEQUENCE: u64 = 0;
const CAPTURED_SPEND_NULLIFIER_ROOT_SEQUENCE: u64 = 1;
const FIXTURE_TREE_HEIGHT: i32 = 40;
const FIXTURE_ROOT_HISTORY_CAPACITY: i64 = 64;
const FIXTURE_MASP_NULLIFIER_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x0b,
];
const FIXTURE_MASP_TX_BLINDING: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x0c,
];
const FIXTURE_MASP_OUTPUT_BLINDING: [u8; 32] = [0xDD; 32];

#[derive(Debug, Clone)]
struct LocalNullifierContext {
    spend_nullifier: [u8; 32],
    indexed_nullifier_address: [u8; 32],
    low_value: [u8; 32],
    next_value: [u8; 32],
    root: [u8; 32],
}

fn program_test_capture_snapshot() -> ProoflessAppendCaptureSnapshot {
    ProoflessAppendCaptureSnapshot::from_json_str(include_str!(
        "../fixtures/shielded_pool_proofless_append_capture.json"
    ))
    .expect("program-test proofless append capture should decode")
}

fn program_test_spend_capture_snapshot() -> ProoflessSpendCaptureSnapshot {
    ProoflessSpendCaptureSnapshot::from_json_str(include_str!(
        "../fixtures/shielded_pool_proofless_spend_capture.json"
    ))
    .expect("program-test proofless spend capture should decode")
}

fn captured_program_test_fixture(
    snapshot: &ProoflessAppendCaptureSnapshot,
) -> CapturedShieldedPoolFixture {
    let owner = FixtureOwnerSpec {
        owner_pubkey: [0xAA; 32],
        token_mint: [0xBB; 32],
        spl_amount: 1_000_000,
        sol_amount: 42,
        blinding: [0xCC; 32],
    };
    let captured_transaction = snapshot
        .to_captured_transaction(Signature::default())
        .expect("program-test capture should convert to Photon transaction");
    FixtureBuilder::proofless_shield_one_output(Signature::default(), owner)
        .build_with_captured_transaction(captured_transaction)
        .expect("program-test capture should match local/dev plaintext sidecar")
}

fn snapshot_utxo_tree(snapshot: &ProoflessAppendCaptureSnapshot) -> [u8; 32] {
    snapshot_pubkey_bytes(&snapshot.expected.utxo_tree)
}

fn snapshot_output_queue(snapshot: &ProoflessAppendCaptureSnapshot) -> [u8; 32] {
    snapshot_pubkey_bytes(&snapshot.expected.output_queue)
}

fn snapshot_nullifier_tree(snapshot: &ProoflessSpendCaptureSnapshot) -> [u8; 32] {
    hex_0x_to_32(&snapshot.expected.nullifier_tree)
}

fn snapshot_pubkey_bytes(value: &str) -> [u8; 32] {
    value
        .parse::<Pubkey>()
        .unwrap_or_else(|err| panic!("invalid snapshot pubkey {value}: {err}"))
        .to_bytes()
}

#[test]
fn zone_rpc_api_fixture_uses_public_facade_methods() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/zone_rpc_api_fixture.json"))
            .expect("Zone RPC API fixture should be valid JSON");
    let methods = value["fixtures"]
        .as_array()
        .expect("fixtures should be an array")
        .iter()
        .map(|fixture| {
            fixture["method"]
                .as_str()
                .expect("fixture method should be a string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        methods,
        [
            "fetch_decrypted_utxos",
            "fetch_proof_inputs",
            "fetch_proofs",
            "fetch_utxos",
            "get_proof_job",
            "get_relayer_job",
            "get_zone_info",
            "submit_intent",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
    );
    let fixture_text = value.to_string();
    assert!(!fixture_text.contains("get_shielded_utxo"));
    assert!(!fixture_text.contains("getShieldedUtxo"));
}

#[named]
#[tokio::test]
#[serial]
async fn test_shielded_pool_captured_append_to_zone_rpc_wiring_sqlite() {
    let name = trim_test_name(function_name!());
    let setup = setup_with_options(
        name.to_string(),
        TestSetupOptions {
            network: Network::Localnet,
            db_backend: DatabaseBackend::Sqlite,
        },
    )
    .await;

    let snapshot = program_test_capture_snapshot();
    let utxo_tree = snapshot_utxo_tree(&snapshot);
    let output_queue = snapshot_output_queue(&snapshot);
    let tree_sequence = snapshot.expected.tree_sequence;
    let batch_append_sequence = snapshot.expected.batch_append_sequence;
    let spend_snapshot = program_test_spend_capture_snapshot();
    let nullifier_tree = snapshot_nullifier_tree(&spend_snapshot);
    let fixture = captured_program_test_fixture(&snapshot);
    let zone_config_hash = fixture
        .event
        .zone_config_hash
        .expect("fixture must be zoned");
    let output = &fixture.event.outputs[0];
    let mut nullifier_context =
        local_nullifier_context_for_fixture(&fixture, 0, nullifier_tree);

    seed_local_fixture_tree_metadata(setup.db_conn.as_ref(), utxo_tree, output_queue).await;
    let mut resolver = TreeResolver::new(setup.client.as_ref());
    let state_update = parse_transaction(
        setup.db_conn.as_ref(),
        &fixture.transaction_info,
        100,
        &mut resolver,
    )
    .await
    .expect("captured shielded append should parse through Photon transaction parser");

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
        tree_sequence
    );
    assert_eq!(
        state_update
            .batch_merkle_tree_events
            .get(&utxo_tree)
            .map(|events| events.len()),
        Some(1),
        "generated capture must include one UTXO batch append event"
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
    .expect("captured shielded transaction slot must have block metadata");

    persist_state_update_using_connection(setup.db_conn.as_ref(), state_update.clone())
        .await
        .expect("first shielded state persist should succeed");
    persist_state_update_using_connection(setup.db_conn.as_ref(), state_update.clone())
        .await
        .expect("re-indexing the same shielded event should be idempotent");
    persist_local_nullifier_fixture(
        setup.db_conn.as_ref(),
        nullifier_tree,
        &mut nullifier_context,
    )
    .await;

    let persisted_nullifiers = shielded_nullifier_events::Entity::find()
        .all(setup.db_conn.as_ref())
        .await
        .expect("persisted nullifier event query should succeed");
    assert!(
        persisted_nullifiers.is_empty(),
        "pre-spend indexed-tree setup must not emit spend/nullifier events"
    );
    assert_eq!(
        address_queues::Entity::find()
            .count(setup.db_conn.as_ref())
            .await
            .unwrap(),
        0,
        "batch address append should consume the seeded nullifier queue rows"
    );

    let persisted_account = accounts::Entity::find_by_id(
        state_update.shielded_outputs[0]
            .compressed_account_hash
            .to_vec(),
    )
    .one(setup.db_conn.as_ref())
    .await
    .expect("persisted compressed account query should succeed")
    .expect("batch append fixture should persist the compressed account row");
    assert_eq!(persisted_account.tree, utxo_tree.to_vec());
    assert_eq!(
        persisted_account.leaf_index,
        fixture_leaf_index_base() as i64
    );
    assert!(
        !persisted_account.in_output_queue,
        "persisted account remained in output queue for tree {}, leaf {}",
        hex_0x(&persisted_account.tree),
        persisted_account.leaf_index
    );

    let persisted_leaf = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(utxo_tree.to_vec()))
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
    assert_eq!(persisted_leaf.seq, Some(batch_append_sequence as i64));

    let persisted_root = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(utxo_tree.to_vec()))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .one(setup.db_conn.as_ref())
        .await
        .expect("persisted state-tree root query should succeed")
        .expect("batch append fixture should persist a UTXO root");
    assert_eq!(persisted_root.seq, Some(batch_append_sequence as i64));

    assert_eq!(
        shielded_utxo_events::Entity::find()
            .count(setup.db_conn.as_ref())
            .await
            .unwrap(),
        1,
        "only the captured append event should persist before the spend lands"
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
    assert_eq!(public_record.sequence_number, tree_sequence);
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
            spend_nullifiers: vec![hex_0x(&nullifier_context.spend_nullifier)],
            nullifier_tree: Some(SerializablePubkey::from(nullifier_tree)),
            shielded_pool_program_id: Some(SerializablePubkey::from(SHIELDED_POOL_TEST_PROGRAM_ID)),
            utxo_root_sequence: Some(batch_append_sequence),
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
        proof_inputs.inputs[0].account_owner_hash,
        decimal_from_bytes(&fixture_light_account_owner_hash())
    );
    assert_eq!(
        proof_inputs.inputs[0].account_tree_hash,
        decimal_from_bytes(&hash_to_bn254_field_size_be(&utxo_tree))
    );
    assert_eq!(
        proof_inputs.inputs[0].account_discriminator,
        decimal_from_bytes(&discriminator_field_bytes(
            fixture_light_account_discriminator()
        ))
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
    assert_eq!(proof_inputs.utxo_root_sequence, Some(batch_append_sequence));
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
        batch_append_sequence % FIXTURE_ROOT_HISTORY_CAPACITY as u64
    );
    assert_eq!(root_context.utxo_root_sequence, batch_append_sequence);
    assert_eq!(root_context.nullifier_tree_id, hex_0x(&nullifier_tree));
    assert_eq!(root_context.nullifier_root, hex_0x(&nullifier_context.root));
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
    assert_eq!(compressed_proof.root_sequence, batch_append_sequence);
    assert_eq!(
        compressed_proof.root_index,
        Some(batch_append_sequence % FIXTURE_ROOT_HISTORY_CAPACITY as u64)
    );
    let nullifier_proof = proof_inputs.inputs[0]
        .nullifier_non_inclusion_proof
        .as_ref()
        .expect("event-backed local fixture should produce nullifier non-inclusion proof");
    assert_eq!(
        nullifier_proof.nullifier,
        hex_0x(&nullifier_context.spend_nullifier)
    );
    assert_eq!(
        nullifier_proof.nullifier_tree,
        SerializablePubkey::from(nullifier_tree)
    );
    assert_eq!(nullifier_proof.root, hex_0x(&nullifier_context.root));
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
        hex_0x(&nullifier_context.low_value)
    );
    assert_eq!(
        nullifier_proof.next_value,
        hex_0x(&nullifier_context.next_value)
    );
    assert_eq!(nullifier_proof.low_leaf_index, 0);
    assert_eq!(nullifier_proof.next_index, 0);

    let proof_requests = zone_rpc
        .build_local_dev_masp_proof_requests(&proof_inputs, &decrypted)
        .expect("Zone RPC should build local/dev MASP proof requests");
    let tree_payload: serde_json::Value =
        serde_json::from_str(&proof_requests[1].payload).expect("tree payload should decode");
    assert_eq!(
        tree_payload["rootContext"],
        serde_json::to_value(proof_inputs.root_context.as_ref().unwrap()).unwrap()
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
    let proof_job_id = proof_job.proof_job_id.clone();
    assert_eq!(proof_job.proof_jobs.len(), 2);
    assert!(proof_job
        .proof_jobs
        .iter()
        .all(|job| job.status == ZoneJobStatus::Succeeded));
    assert!(proof_job
        .proof_jobs
        .iter()
        .all(|job| job.public_inputs_hash.is_some() && job.verifier_inputs.is_some()));
    let proof_job_status = zone_rpc
        .get_proof_job(GetProofJobRequest {
            proof_job_id: proof_job_id.clone(),
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
            intent: test_relayer_intent(&proof_job_id, &proof_inputs),
        })
        .await
        .expect("local/dev Zone RPC should create relayer jobs");
    let relayer_job_status = zone_rpc
        .get_relayer_job(GetRelayerJobRequest {
            relayer_job_id: relayer_job.relayer_job_id,
        })
        .await
        .expect("relayer job should be readable");
    assert_eq!(relayer_job_status.status, ZoneJobStatus::Succeeded);
    let relayer_result: serde_json::Value =
        serde_json::from_str(relayer_job_status.result.as_deref().unwrap())
            .expect("relayer result should be JSON");
    assert_eq!(relayer_result["status"], "localTransactionCandidateBuilt");
    assert_eq!(relayer_result["rootStatus"], "providedAndBoundToProofs");
    assert_eq!(relayer_result["localVerifier"]["status"], "verified");
    assert_eq!(
        relayer_result["transactionCandidate"]["kind"],
        "local-dev-verifier-instruction"
    );
    assert_eq!(
        relayer_result["transactionCandidate"]["unsignedTransaction"]["instructions"][0]
            ["dataEncoding"],
        "hex-json"
    );
    assert!(
        relayer_result["transactionCandidate"]["unsignedTransaction"]["instructions"][0]["data"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );

    let spend_signature = Signature::from([0x99; 64]);
    let spend_snapshot = program_test_spend_capture_snapshot();
    spend_snapshot
        .validate()
        .expect("captured spend fixture should match emitted event bytes");
    let spend_transaction_info = spend_snapshot
        .to_captured_transaction(spend_signature)
        .expect("captured spend fixture should convert to Photon transaction")
        .to_transaction_info();
    let mut resolver = TreeResolver::new(setup.client.as_ref());
    let spend_state_update = parse_transaction(
        setup.db_conn.as_ref(),
        &spend_transaction_info,
        102,
        &mut resolver,
    )
    .await
    .expect("captured shielded spend should parse through Photon transaction parser");
    assert_eq!(spend_state_update.shielded_tx_events.len(), 1);
    assert_eq!(spend_state_update.shielded_outputs.len(), 0);
    assert_eq!(spend_state_update.shielded_nullifier_events.len(), 1);
    assert_eq!(
        spend_state_update.shielded_tx_events[0].input_nullifiers,
        vec![nullifier_context.spend_nullifier]
    );
    assert_eq!(
        spend_state_update.shielded_tx_events[0].nullifier_chain,
        Some(nullifier_context.spend_nullifier)
    );
    assert_eq!(
        spend_state_update.shielded_nullifier_events[0].nullifier,
        nullifier_context.spend_nullifier
    );
    assert_eq!(
        spend_state_update.shielded_nullifier_events[0].nullifier_tree,
        nullifier_tree
    );
    assert_eq!(
        spend_state_update.batch_new_addresses.len(),
        1,
        "captured spend should enqueue one derived AddressV2 nullifier"
    );
    assert_eq!(
        spend_state_update.batch_new_addresses[0].tree,
        SerializablePubkey::from(nullifier_tree)
    );
    assert_eq!(
        spend_state_update.batch_new_addresses[0].address,
        nullifier_context.indexed_nullifier_address
    );
    let captured_spend_queue_index = spend_state_update.batch_new_addresses[0].queue_index;
    blocks::Entity::insert(blocks::ActiveModel {
        slot: sea_orm::Set(102),
        parent_slot: sea_orm::Set(101),
        parent_blockhash: sea_orm::Set(vec![2u8; 32]),
        blockhash: sea_orm::Set(vec![3u8; 32]),
        block_height: sea_orm::Set(102),
        block_time: sea_orm::Set(0),
    })
    .exec(setup.db_conn.as_ref())
    .await
    .expect("captured shielded spend slot must have block metadata");
    persist_state_update_using_connection(setup.db_conn.as_ref(), spend_state_update.clone())
        .await
        .expect("captured shielded spend persist should succeed");
    persist_state_update_using_connection(setup.db_conn.as_ref(), spend_state_update)
        .await
        .expect("re-indexing captured shielded spend should be idempotent");
    let persisted_spend_nullifier =
        shielded_nullifier_events::Entity::find_by_id(nullifier_context.spend_nullifier.to_vec())
            .one(setup.db_conn.as_ref())
            .await
            .expect("persisted spend nullifier query should succeed")
            .expect("captured spend should persist the spent nullifier");
    assert_eq!(
        persisted_spend_nullifier.nullifier_tree,
        nullifier_tree.to_vec()
    );
    assert_eq!(
        persisted_spend_nullifier.tx_signature,
        Into::<[u8; 64]>::into(spend_signature).to_vec()
    );
    assert_eq!(
        shielded_utxo_events::Entity::find()
            .count(setup.db_conn.as_ref())
            .await
            .unwrap(),
        2,
        "append event and captured spend event should persist"
    );
    assert_eq!(
        shielded_nullifier_events::Entity::find()
            .count(setup.db_conn.as_ref())
            .await
            .unwrap(),
        1,
        "only the captured spend nullifier should persist"
    );
    let queued_nullifier_address = address_queues::Entity::find()
        .filter(address_queues::Column::Tree.eq(nullifier_tree.to_vec()))
        .filter(
            address_queues::Column::Address.eq(nullifier_context.indexed_nullifier_address.to_vec()),
        )
        .one(setup.db_conn.as_ref())
        .await
        .expect("captured spend queue-row query should succeed")
        .expect("captured spend should persist the derived nullifier address queue row");
    assert_eq!(
        queued_nullifier_address.queue_index as u64,
        captured_spend_queue_index,
        "persisted address queue row should preserve the Light event queue index"
    );

    persist_captured_nullifier_batch_append(
        setup.db_conn.as_ref(),
        nullifier_tree,
        queued_nullifier_address,
    )
    .await;
    assert_eq!(
        address_queues::Entity::find()
            .filter(address_queues::Column::Tree.eq(nullifier_tree.to_vec()))
            .filter(
                address_queues::Column::Address
                    .eq(nullifier_context.indexed_nullifier_address.to_vec())
            )
            .count(setup.db_conn.as_ref())
            .await
            .unwrap(),
        0,
        "captured nullifier batch append should consume the spend queue row"
    );
    let indexed_spend_nullifier = indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(nullifier_tree.to_vec()))
        .filter(indexed_trees::Column::Value.eq(nullifier_context.indexed_nullifier_address.to_vec()))
        .one(setup.db_conn.as_ref())
        .await
        .expect("indexed captured nullifier query should succeed")
        .expect("captured nullifier batch append should index the derived nullifier address");
    assert_eq!(
        indexed_spend_nullifier.seq,
        Some(CAPTURED_SPEND_NULLIFIER_ROOT_SEQUENCE as i64)
    );
    let captured_spend_nullifier_root = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(nullifier_tree.to_vec()))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .filter(state_trees::Column::Seq.eq(Some(
            CAPTURED_SPEND_NULLIFIER_ROOT_SEQUENCE as i64,
        )))
        .one(setup.db_conn.as_ref())
        .await
        .expect("captured spend nullifier root query should succeed")
        .expect("captured nullifier batch append should persist a post-spend root");
    assert_eq!(
        captured_spend_nullifier_root.seq,
        Some(CAPTURED_SPEND_NULLIFIER_ROOT_SEQUENCE as i64)
    );
    let historical_relayer_job = zone_rpc
        .submit_intent(SubmitIntentRequest {
            intent: test_relayer_intent(&proof_job_id, &proof_inputs),
        })
        .await
        .expect("local verifier should accept historical pre-spend nullifier roots after append");
    let historical_relayer_job_status = zone_rpc
        .get_relayer_job(GetRelayerJobRequest {
            relayer_job_id: historical_relayer_job.relayer_job_id,
        })
        .await
        .expect("historical-root relayer job should be readable");
    assert_eq!(historical_relayer_job_status.status, ZoneJobStatus::Succeeded);

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

async fn seed_local_fixture_tree_metadata(
    conn: &sea_orm::DatabaseConnection,
    utxo_tree: [u8; 32],
    output_queue: [u8; 32],
) {
    accounts::Entity::delete_many()
        .filter(accounts::Column::Tree.eq(utxo_tree.to_vec()))
        .exec(conn)
        .await
        .expect("local fixture should clear existing UTXO accounts");
    state_trees::Entity::delete_many()
        .filter(state_trees::Column::Tree.eq(utxo_tree.to_vec()))
        .exec(conn)
        .await
        .expect("local fixture should clear existing UTXO state tree rows");
    tree_metadata::Entity::delete_many()
        .filter(
            tree_metadata::Column::TreePubkey
                .eq(utxo_tree.to_vec())
                .or(tree_metadata::Column::TreePubkey.eq(output_queue.to_vec())),
        )
        .exec(conn)
        .await
        .expect("local fixture should replace existing UTXO tree metadata");

    tree_metadata::Entity::insert(tree_metadata::ActiveModel {
        tree_pubkey: Set(utxo_tree.to_vec()),
        queue_pubkey: Set(output_queue.to_vec()),
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

async fn persist_local_nullifier_fixture(
    conn: &sea_orm::DatabaseConnection,
    nullifier_tree: [u8; 32],
    context: &mut LocalNullifierContext,
) {
    tree_metadata::Entity::insert(tree_metadata::ActiveModel {
        tree_pubkey: Set(nullifier_tree.to_vec()),
        queue_pubkey: Set(nullifier_tree.to_vec()),
        tree_type: Set(tree_type_id(TreeType::AddressV2)),
        height: Set(FIXTURE_TREE_HEIGHT),
        root_history_capacity: Set(FIXTURE_ROOT_HISTORY_CAPACITY),
        sequence_number: Set(FIXTURE_NULLIFIER_ROOT_SEQUENCE as i64),
        next_index: Set(1),
        last_synced_slot: Set(100),
    })
    .exec(conn)
    .await
    .expect("local fixture should seed nullifier tree metadata");

    context.root = empty_address_tree_root(nullifier_tree);
    state_trees::Entity::insert(state_trees::ActiveModel {
        tree: Set(nullifier_tree.to_vec()),
        node_idx: Set(1),
        leaf_idx: Set(None),
        level: Set(FIXTURE_TREE_HEIGHT as i64),
        hash: Set(context.root.to_vec()),
        seq: Set(Some(FIXTURE_NULLIFIER_ROOT_SEQUENCE as i64)),
    })
    .exec(conn)
    .await
    .expect("local fixture should seed the empty nullifier-tree root");
    state_tree_histories::Entity::insert(state_tree_histories::ActiveModel {
        tree: Set(nullifier_tree.to_vec()),
        seq: Set(FIXTURE_NULLIFIER_ROOT_SEQUENCE as i64),
        leaf_idx: Set(0),
        transaction_signature: Set(vec![0; 64]),
        root_hash: Set(Some(context.root.to_vec())),
    })
    .exec(conn)
    .await
    .expect("local fixture should seed the empty nullifier-tree root history");

    let persisted_root = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(nullifier_tree.to_vec()))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .filter(state_trees::Column::Seq.eq(Some(FIXTURE_NULLIFIER_ROOT_SEQUENCE as i64)))
        .one(conn)
        .await
        .expect("local nullifier fixture root query should succeed")
        .expect("local nullifier fixture should persist a root");
    assert_eq!(persisted_root.hash, context.root.to_vec());
}

fn empty_address_tree_root(nullifier_tree: [u8; 32]) -> [u8; 32] {
    let zeroeth_leaf = get_zeroeth_exclusion_range(nullifier_tree.to_vec());
    let zeroeth_hash =
        compute_range_node_hash_v2(&zeroeth_leaf).expect("empty AddressV2 leaf hash should compute");
    let mut root = zeroeth_hash.to_vec();
    for zero in ZERO_BYTES.iter().take(FIXTURE_TREE_HEIGHT as usize) {
        root = compute_parent_hash(root, zero.to_vec())
            .expect("empty AddressV2 root hash should compute");
    }
    root.try_into()
        .expect("empty AddressV2 root should be 32 bytes")
}

async fn persist_captured_nullifier_batch_append(
    conn: &sea_orm::DatabaseConnection,
    nullifier_tree: [u8; 32],
    queued_nullifier_address: address_queues::Model,
) {
    let current_next_index = indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(nullifier_tree.to_vec()))
        .order_by_desc(indexed_trees::Column::LeafIndex)
        .one(conn)
        .await
        .expect("current indexed nullifier-tree query should succeed")
        .map(|row| (row.leaf_index + 1) as u64)
        .unwrap_or(1);
    let old_next_index = queued_nullifier_address.queue_index as u64 + 1;
    assert_eq!(
        old_next_index,
        current_next_index,
        "captured spend queue index must match the pre-spend indexed nullifier tree: \
         queue_index={} implies old_next_index={}, but Photon is at current_next_index={}",
        queued_nullifier_address.queue_index,
        old_next_index,
        current_next_index
    );

    let mut state_update = StateUpdate::new();
    state_update
        .batch_merkle_tree_events
        .entry(nullifier_tree)
        .or_default()
        .push((
            CAPTURED_SPEND_NULLIFIER_ROOT_SEQUENCE,
            MerkleTreeEvent::BatchAddressAppend(BatchEvent {
                merkle_tree_pubkey: nullifier_tree,
                batch_index: 1,
                zkp_batch_index: 0,
                zkp_batch_size: 1,
                old_next_index,
                new_next_index: old_next_index + 1,
                new_root: [0xA8; 32],
                root_index: (CAPTURED_SPEND_NULLIFIER_ROOT_SEQUENCE
                    % FIXTURE_ROOT_HISTORY_CAPACITY as u64) as u32,
                sequence_number: CAPTURED_SPEND_NULLIFIER_ROOT_SEQUENCE,
                output_queue_pubkey: Some(nullifier_tree),
            }),
        ));
    state_update.transactions.insert(
        photon_indexer::ingester::parser::state_update::Transaction {
            signature: Signature::from([0x43; 64]),
            slot: 103,
            uses_compression: true,
            error: None,
        },
    );

    blocks::Entity::insert(blocks::ActiveModel {
        slot: Set(103),
        parent_slot: Set(102),
        parent_blockhash: Set(vec![3u8; 32]),
        blockhash: Set(vec![4u8; 32]),
        block_height: Set(103),
        block_time: Set(0),
    })
    .exec(conn)
    .await
    .expect("captured nullifier batch append slot must have block metadata");

    persist_state_update_using_connection(conn, state_update.clone())
        .await
        .expect("captured nullifier batch append should persist through Photon state update");
    persist_state_update_using_connection(conn, state_update)
        .await
        .expect("re-indexing captured nullifier batch append should be idempotent");
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

fn local_masp_witness_secrets(fixture: &CapturedShieldedPoolFixture) -> LocalMaspWitnessSecrets {
    let inputs = fixture
        .sidecar
        .payloads
        .iter()
        .map(|payload| LocalMaspInputSecret {
            owner: payload.owner_hash,
            spl_amount: payload.spl_amount,
            sol_amount: payload.sol_amount,
            blinding: field_bytes(payload.blinding),
            data_hash: payload.data_hash,
            program_id: fixture_masp_program_id(),
            seed: fixture_masp_input_seed(),
        })
        .collect::<Vec<_>>();
    let total_spl = inputs.iter().map(|input| input.spl_amount).sum::<u64>();
    let total_sol = inputs.iter().map(|input| input.sol_amount).sum::<u64>();
    let first_input = inputs
        .first()
        .expect("local/dev MASP fixture requires one input");
    let output_seed = fixture_masp_output_seed();
    let output_owner = masp_program_owner_hash(&first_input.program_id, output_seed);
    let output_data_hash = first_input.data_hash;

    LocalMaspWitnessSecrets {
        inputs,
        outputs: vec![LocalMaspOutputSecret {
            owner: output_owner,
            spl_amount: total_spl,
            sol_amount: total_sol,
            blinding: field_bytes(FIXTURE_MASP_OUTPUT_BLINDING),
            data_hash: output_data_hash,
            owner_is_program: true,
            owner_program_index: 0,
            seed: output_seed,
        }],
        nullifier_secret: FIXTURE_MASP_NULLIFIER_SECRET,
        tx_blinding: FIXTURE_MASP_TX_BLINDING,
    }
}

fn local_nullifier_context_for_fixture(
    fixture: &CapturedShieldedPoolFixture,
    output_index: usize,
    nullifier_tree: [u8; 32],
) -> LocalNullifierContext {
    let output = fixture
        .event
        .outputs
        .get(output_index)
        .expect("fixture output exists");
    let leaf_index = fixture_leaf_index_base() as u64 + output_index as u64;
    let domain_dns = poseidon_hash_fields(&[&output.utxo_hash, &fixture_masp_program_id()]);
    let leaf_index_bytes = u64_to_be_32(leaf_index);
    let spend_nullifier =
        poseidon_hash_fields(&[&output.utxo_hash, &leaf_index_bytes, &domain_dns]);
    let indexed_nullifier_address = derive_address(
        &spend_nullifier,
        &nullifier_tree,
        &SHIELDED_POOL_TEST_PROGRAM_ID.to_bytes(),
    );
    let zeroeth_leaf = get_zeroeth_exclusion_range(nullifier_tree.to_vec());
    let low_value: [u8; 32] = zeroeth_leaf
        .value
        .try_into()
        .expect("zeroeth AddressV2 value should be 32 bytes");
    let next_value: [u8; 32] = zeroeth_leaf
        .next_value
        .try_into()
        .expect("zeroeth AddressV2 next value should be 32 bytes");
    let indexed_nullifier_int = BigUint::from_bytes_be(&indexed_nullifier_address);
    let highest_address_plus_one = BigUint::from_bytes_be(&next_value);
    assert!(
        indexed_nullifier_int > BigUint::from(0u8)
            && indexed_nullifier_int < highest_address_plus_one,
        "fixture indexed nullifier address must be inside the empty AddressV2 range"
    );
    LocalNullifierContext {
        spend_nullifier,
        indexed_nullifier_address,
        low_value,
        next_value,
        root: [0; 32],
    }
}

fn masp_program_owner_hash(program_id: &[u8; 32], seed: u64) -> [u8; 32] {
    let seed = u64_to_be_32(seed);
    poseidon_hash_fields(&[program_id, &seed])
}

fn poseidon_hash_fields(inputs: &[&[u8; 32]]) -> [u8; 32] {
    let mut hasher =
        Poseidon::<Fr>::new_circom(inputs.len()).expect("fixture poseidon should initialize");
    let input_slices = inputs
        .iter()
        .map(|input| input.as_slice())
        .collect::<Vec<_>>();
    hasher
        .hash_bytes_be(&input_slices)
        .expect("fixture poseidon hash should succeed")
}

fn field_bytes(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] = 0;
    bytes
}

fn discriminator_field_bytes(discriminator: [u8; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&discriminator);
    out
}

fn u64_to_be_32(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn decimal_from_bytes(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_str_radix(10)
}

async fn zone_rpc_fixture_with_proof_inputs(
    name: &str,
    prover_url: String,
) -> (
    ZoneRpcApi,
    FetchProofInputsResponse,
    Vec<ZoneDecryptedUtxoView>,
    LocalMaspWitnessSecrets,
) {
    let setup = setup_with_options(
        name.to_string(),
        TestSetupOptions {
            network: Network::Localnet,
            db_backend: DatabaseBackend::Sqlite,
        },
    )
    .await;

    let snapshot = program_test_capture_snapshot();
    let utxo_tree = snapshot_utxo_tree(&snapshot);
    let output_queue = snapshot_output_queue(&snapshot);
    let batch_append_sequence = snapshot.expected.batch_append_sequence;
    let spend_snapshot = program_test_spend_capture_snapshot();
    let nullifier_tree = snapshot_nullifier_tree(&spend_snapshot);
    let fixture = captured_program_test_fixture(&snapshot);
    let zone_config_hash = fixture
        .event
        .zone_config_hash
        .expect("fixture must be zoned");
    let output = &fixture.event.outputs[0];
    let mut nullifier_context =
        local_nullifier_context_for_fixture(&fixture, 0, nullifier_tree);

    seed_local_fixture_tree_metadata(setup.db_conn.as_ref(), utxo_tree, output_queue).await;
    let mut resolver = TreeResolver::new(setup.client.as_ref());
    let state_update = parse_transaction(
        setup.db_conn.as_ref(),
        &fixture.transaction_info,
        100,
        &mut resolver,
    )
    .await
    .expect("captured shielded append should parse through Photon transaction parser");

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
    .expect("captured shielded transaction slot must have block metadata");

    persist_state_update_using_connection(setup.db_conn.as_ref(), state_update.clone())
        .await
        .expect("shielded state persist should succeed");
    persist_local_nullifier_fixture(
        setup.db_conn.as_ref(),
        nullifier_tree,
        &mut nullifier_context,
    )
    .await;

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
            spend_nullifiers: vec![hex_0x(&nullifier_context.spend_nullifier)],
            nullifier_tree: Some(SerializablePubkey::from(nullifier_tree)),
            shielded_pool_program_id: Some(SerializablePubkey::from(SHIELDED_POOL_TEST_PROGRAM_ID)),
            utxo_root_sequence: Some(batch_append_sequence),
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

    (
        zone_rpc,
        proof_inputs,
        decrypted,
        local_masp_witness_secrets(&fixture),
    )
}

fn generate_masp_local_dev_proof_requests(
    zone_rpc: &ZoneRpcApi,
    proof_inputs: &FetchProofInputsResponse,
    decrypted_inputs: &[ZoneDecryptedUtxoView],
    secrets: &LocalMaspWitnessSecrets,
) -> MaspLocalDevProofPayloads {
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
    let spec_path = std::env::temp_dir().join(format!(
        "light-masp-local-dev-zone-spec-{}.json",
        std::process::id()
    ));
    let spec = zone_rpc
        .build_local_dev_masp_zone_fixture_spec(proof_inputs, decrypted_inputs, secrets)
        .expect("Zone RPC should assemble local/dev MASP witness spec");
    std::fs::write(
        &spec_path,
        serde_json::to_vec_pretty(&spec).expect("local/dev MASP spec should encode"),
    )
    .unwrap_or_else(|err| panic!("failed to write {spec_path:?}: {err}"));

    let status = Command::new(&go_bin)
        .arg("test")
        .arg("./prover/masp")
        .arg("-run")
        .arg("TestExportLocalDevProofRequestFixtures")
        .arg("-count=1")
        .env("MASP_FIXTURE_OUT", &output_path)
        .env("MASP_ZONE_FIXTURE_SPEC", &spec_path)
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
    let _ = std::fs::remove_file(spec_path);
    parsed
}

#[tokio::test]
#[serial]
#[ignore = "spawns Go prover-server and generates real Groth16 proofs"]
async fn test_zone_rpc_fetch_proofs_against_real_masp_prover() {
    let prover = spawn_real_masp_prover().await;
    let (zone_rpc, proof_inputs, decrypted, secrets) =
        zone_rpc_fixture_with_proof_inputs("zone_rpc_real_masp_prover", prover.url.clone()).await;
    let fixtures =
        generate_masp_local_dev_proof_requests(&zone_rpc, &proof_inputs, &decrypted, &secrets);

    let proof_job = zone_rpc
        .fetch_proofs(FetchProofsRequest {
            intent: test_intent(),
            proof_requests: proof_requests_from_local_dev_payloads(fixtures)
                .expect("generated MASP payloads should convert to prover requests"),
            prover_mode: Some(ProverProofMode::Sync),
        })
        .await
        .expect("Zone RPC should submit real MASP proof requests to prover-server");

    let proof_job_id = proof_job.proof_job_id.clone();
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
            proof_job_id: proof_job_id.clone(),
        })
        .await
        .expect("Zone RPC should store the real proof job aggregate");
    assert_eq!(proof_job_status.status, ZoneJobStatus::Succeeded);
    let result = proof_job_status.result.as_deref().unwrap();
    assert!(result.contains("masp-utxo"));
    assert!(result.contains("masp-tree"));
    assert!(result.contains("ar"));
    assert!(result.contains("krs"));

    let relayer_job = zone_rpc
        .submit_intent(SubmitIntentRequest {
            intent: test_relayer_intent(&proof_job_id, &proof_inputs),
        })
        .await
        .expect("real MASP proof job should feed the local verifier/relayer boundary");
    let relayer_status = zone_rpc
        .get_relayer_job(GetRelayerJobRequest {
            relayer_job_id: relayer_job.relayer_job_id,
        })
        .await
        .expect("real-proof relayer job should be readable");
    assert_eq!(relayer_status.status, ZoneJobStatus::Succeeded);
    let relayer_result: serde_json::Value =
        serde_json::from_str(relayer_status.result.as_deref().unwrap())
            .expect("real-proof relayer result should be JSON");
    assert_eq!(relayer_result["rootStatus"], "providedAndBoundToProofs");
    assert_eq!(relayer_result["localVerifier"]["status"], "verified");
}

#[tokio::test]
#[serial]
#[ignore = "requires TEST_REDIS_URL plus Go prover-server; generates real Groth16 proofs through Redis queue workers"]
async fn test_zone_rpc_fetch_proofs_async_against_real_masp_prover_redis() {
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        eprintln!("set TEST_REDIS_URL, for example redis://localhost:6379/15");
        return;
    };
    let prover = spawn_real_masp_prover_with_redis(redis_url).await;
    let (zone_rpc, proof_inputs, decrypted, secrets) =
        zone_rpc_fixture_with_proof_inputs("zone_rpc_real_masp_prover_redis", prover.url.clone())
            .await;
    let fixtures =
        generate_masp_local_dev_proof_requests(&zone_rpc, &proof_inputs, &decrypted, &secrets);

    let proof_job = zone_rpc
        .fetch_proofs(FetchProofsRequest {
            intent: test_intent(),
            proof_requests: proof_requests_from_local_dev_payloads(fixtures)
                .expect("generated MASP payloads should convert to prover requests"),
            prover_mode: Some(ProverProofMode::Async),
        })
        .await
        .expect("Zone RPC should submit async MASP proof requests to prover-server");

    assert_eq!(proof_job.proof_jobs.len(), 2);
    assert!(proof_job
        .proof_jobs
        .iter()
        .all(|job| job.prover_job_id.is_some()));

    let mut last_status = None;
    for _ in 0..180 {
        let status = zone_rpc
            .get_proof_job(GetProofJobRequest {
                proof_job_id: proof_job.proof_job_id.clone(),
            })
            .await
            .expect("Zone RPC should refresh async proof job status");
        if status.status == ZoneJobStatus::Succeeded {
            let result = status.result.as_deref().unwrap();
            assert!(result.contains("masp-utxo"));
            assert!(result.contains("masp-tree"));
            assert!(result.contains("ar"));
            assert!(result.contains("krs"));
            return;
        }
        if status.status == ZoneJobStatus::Failed {
            panic!("async MASP proof job failed: {:?}", status.error);
        }
        last_status = Some(status.status);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!("async MASP proof job did not finish; last status: {last_status:?}");
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
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

fn test_relayer_intent(
    proof_job_id: &str,
    proof_inputs: &FetchProofInputsResponse,
) -> SignedZoneIntent {
    let root_context = proof_inputs
        .root_context
        .as_ref()
        .expect("relayer intent requires root context");
    let payload = serde_json::json!({
        "proofJobId": proof_job_id,
        "rootContext": root_context,
        "verifierAccounts": {
            "verifierProgramId": Pubkey::new_from_array([0x90; 32]).to_string(),
            "feePayer": Pubkey::new_from_array([0x91; 32]).to_string(),
            "relayerAuthority": Pubkey::new_from_array([0x92; 32]).to_string(),
            "utxoTree": pubkey_from_hex_0x(&root_context.utxo_tree_id).to_string(),
            "nullifierTree": pubkey_from_hex_0x(&root_context.nullifier_tree_id).to_string(),
            "compressionProgram": Pubkey::new_from_array([0x93; 32]).to_string(),
            "noopProgram": Pubkey::new_from_array([0x94; 32]).to_string(),
            "systemProgram": Pubkey::default().to_string()
        },
        "recentBlockhash": "local-dev-blockhash"
    });

    SignedZoneIntent {
        intent_hash: hex_0x(&[0x44; 32]),
        intent_payload: payload.to_string(),
        signer: "local-dev-signer".to_string(),
        signature: "local-dev-signature".to_string(),
    }
}

fn pubkey_from_hex_0x(value: &str) -> Pubkey {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .unwrap_or_else(|err| panic!("invalid hex pubkey {value}: {err}"));
    Pubkey::new_from_array(
        bytes
            .try_into()
            .unwrap_or_else(|_| panic!("hex pubkey {value} must be 32 bytes")),
    )
}

fn hex_0x_to_32(value: &str) -> [u8; 32] {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .unwrap_or_else(|err| panic!("invalid 32-byte hex value {value}: {err}"))
        .try_into()
        .unwrap_or_else(|_| panic!("hex value {value} must be 32 bytes"))
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
    spawn_real_masp_prover_with_options(None).await
}

async fn spawn_real_masp_prover_with_redis(redis_url: String) -> ProverProcess {
    spawn_real_masp_prover_with_options(Some(redis_url)).await
}

async fn spawn_real_masp_prover_with_options(redis_url: Option<String>) -> ProverProcess {
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

    let mut command = Command::new(&go_bin);
    command
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
        .arg(keys_dir);
    if let Some(redis_url) = redis_url {
        command.arg("--redis-url").arg(redis_url);
    }
    let mut child = command
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
