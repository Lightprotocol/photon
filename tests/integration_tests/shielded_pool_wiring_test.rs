use function_name::named;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use photon_indexer::dao::generated::{
    blocks, shielded_utxo_events, shielded_utxo_outputs, zone_configs,
};
use photon_indexer::ingester::parser::{
    parse_transaction,
    shielded_pool_test_fixture::{FixtureBuilder, FixtureOwnerSpec},
    TreeResolver,
};
use photon_indexer::zone_rpc::api::{
    FetchDecryptedUtxosRequest, FetchProofInputsRequest, FetchProofsRequest, FetchUtxosRequest,
    GetProofJobRequest, GetRelayerJobRequest, GetZoneInfoRequest, SignedZoneIntent,
    SubmitIntentRequest, ZoneJobStatus, ZoneRpcApi,
};
use photon_indexer::zone_rpc::plaintext_projection::{
    ZonePlaintextProjector, ZoneRpcProjectionConfig,
};
use photon_indexer::zone_rpc::private_api::{ZoneQueryAuthorization, ZoneRpcPrivateApi};
use photon_indexer::zone_rpc::private_db::{migrate_zone_private_db, SqlZonePrivateStore};
use photon_indexer::zone_rpc::prover_client::{
    ProverProofClient, ProverProofMode, ProverProofRequest,
};
use photon_indexer::zone_rpc::workers::{
    DecryptOutputsRequest, Decryptor, EncryptedUtxoInput, LocalPassthroughDecryptor,
};
use sea_orm::{Database, EntityTrait, PaginatorTrait};
use serde::Deserialize;
use serial_test::serial;
use solana_signature::Signature;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use crate::utils::*;

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
        name,
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
    assert_eq!(state_update.shielded_outputs[0].leaf_index, 100);
    assert_eq!(state_update.shielded_outputs[0].tree_sequence, 7);

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
    assert_eq!(public_record.leaf_index, 100);
    assert_eq!(public_record.sequence_number, 7);
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
            recent_root_preference: None,
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

    let proof_job = zone_rpc
        .fetch_proofs(FetchProofsRequest {
            intent: test_intent(),
            proof_requests: vec![ProverProofRequest {
                circuit_type: "masp-utxo".to_string(),
                payload: r#"{"circuitType":"masp-utxo","nInputs":1,"nOutputs":1,"publicInputsHash":"1","rootContext":{},"localWitness":{"stub":true}}"#.to_string(),
            }],
            prover_mode: Some(ProverProofMode::Sync),
        })
        .await
        .expect("local/dev Zone RPC should submit proof jobs to prover-server");
    assert_eq!(proof_job.proof_jobs.len(), 1);
    assert_eq!(proof_job.proof_jobs[0].status, ZoneJobStatus::Succeeded);
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

#[tokio::test]
#[serial]
#[ignore = "spawns Go prover-server and generates real Groth16 proofs"]
async fn test_zone_rpc_fetch_proofs_against_real_masp_prover() {
    let prover = spawn_real_masp_prover().await;
    let fixtures: MaspLocalDevProofRequests =
        serde_json::from_str(include_str!("../data/masp_local_dev_proof_requests.json"))
            .expect("MASP local/dev proof request fixtures must decode");

    let photon_conn = Arc::new(
        Database::connect("sqlite::memory:")
            .await
            .expect("Photon sqlite db should open"),
    );
    let private_conn = Database::connect("sqlite::memory:")
        .await
        .expect("private Zone RPC sqlite db should open");
    migrate_zone_private_db(&private_conn)
        .await
        .expect("private Zone RPC schema should migrate");
    let private_api =
        ZoneRpcPrivateApi::new_unchecked_for_local_testing(SqlZonePrivateStore::new(private_conn));
    let zone_rpc = ZoneRpcApi::with_proof_client(
        photon_conn,
        private_api,
        ProverProofClient::new(prover.url.clone(), None),
    );

    let proof_job = zone_rpc
        .fetch_proofs(FetchProofsRequest {
            intent: test_intent(),
            proof_requests: vec![
                proof_request_from_fixture("masp-utxo", fixtures.utxo),
                proof_request_from_fixture("masp-tree", fixtures.tree),
            ],
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

fn proof_request_from_fixture(
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
