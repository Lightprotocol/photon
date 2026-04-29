use function_name::named;
use photon_indexer::api::method::get_shielded_utxos::{
    GetShieldedUtxoRequest, GetShieldedUtxosByZoneRequest,
};
use photon_indexer::dao::generated::{
    blocks, shielded_utxo_events, shielded_utxo_outputs, zone_configs,
};
use photon_indexer::ingester::parser::{
    parse_transaction,
    shielded_pool_test_fixture::{FixtureBuilder, FixtureOwnerSpec},
    TreeResolver,
};
use photon_indexer::zone_rpc::plaintext_projection::{
    ZonePlaintextProjector, ZoneRpcProjectionConfig,
};
use photon_indexer::zone_rpc::private_api::{
    GetZoneUtxosByOwnerHashRequest, ZoneQueryAuthorization, ZoneRpcPrivateApi,
};
use photon_indexer::zone_rpc::private_db::{migrate_zone_private_db, SqlZonePrivateStore};
use photon_indexer::zone_rpc::workers::{
    DecryptOutputsRequest, Decryptor, EncryptedUtxoInput, LocalPassthroughDecryptor,
};
use sea_orm::{Database, EntityTrait, PaginatorTrait};
use serial_test::serial;
use solana_signature::Signature;

use crate::utils::*;

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

    let public_record = setup
        .api
        .get_shielded_utxo(GetShieldedUtxoRequest {
            utxo_hash: hex_0x(&output.utxo_hash),
        })
        .await
        .expect("public Photon shielded UTXO API should succeed")
        .value
        .expect("public Photon API should return indexed UTXO");

    assert_eq!(public_record.utxo_hash, hex_0x(&output.utxo_hash));
    assert_eq!(public_record.encrypted_utxo, hex_0x(&output.encrypted_utxo));
    assert_eq!(
        public_record.event.operation_commitment,
        hex_0x(&fixture.event.operation_commitment)
    );
    assert_eq!(
        public_record.event.zone_config_hash,
        Some(hex_0x(&zone_config_hash))
    );

    let public_json = serde_json::to_string(&public_record).unwrap();
    assert!(!public_json.contains("ownerPubkey"));
    assert!(!public_json.contains("blinding"));
    assert!(!public_json.contains("1000000"));

    let by_zone = setup
        .api
        .get_shielded_utxos_by_zone(GetShieldedUtxosByZoneRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
            limit: Some(10),
            before_slot: None,
        })
        .await
        .expect("public zone-filtered UTXO API should succeed");
    assert_eq!(by_zone.items.len(), 1);
    assert_eq!(by_zone.items[0].utxo_hash, hex_0x(&output.utxo_hash));

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
    let private_db = Database::connect("sqlite::memory:")
        .await
        .expect("private Zone RPC sqlite db should open");
    migrate_zone_private_db(&private_db)
        .await
        .expect("private Zone RPC schema should migrate");
    let private_store = SqlZonePrivateStore::new(private_db);
    private_store
        .upsert_many(decrypted_rows.clone())
        .await
        .expect("Zone private store should accept projected rows");
    private_store
        .upsert_many(decrypted_rows)
        .await
        .expect("Zone private store should be idempotent");

    let zone_rpc = ZoneRpcPrivateApi::new_unchecked_for_local_testing(private_store);
    let decrypted = zone_rpc
        .get_decrypted_utxos_by_owner_hash(GetZoneUtxosByOwnerHashRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
            owner_hash: hex_0x(&owner_hash),
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

    assert!(zone_rpc
        .get_decrypted_utxos_by_owner_hash(GetZoneUtxosByOwnerHashRequest {
            zone_config_hash: hex_0x(&zone_config_hash),
            owner_hash: hex_0x(&[0x11; 32]),
            authorization: test_authorization(),
            include_spent: None,
            limit: Some(10),
        })
        .await
        .unwrap()
        .items
        .is_empty());
    assert!(zone_rpc
        .get_decrypted_utxos_by_owner_hash(GetZoneUtxosByOwnerHashRequest {
            zone_config_hash: hex_0x(&[0x22; 32]),
            owner_hash: hex_0x(&owner_hash),
            authorization: test_authorization(),
            include_spent: None,
            limit: Some(10),
        })
        .await
        .unwrap()
        .items
        .is_empty());
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
