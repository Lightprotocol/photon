//! Persistence for zoned shielded-pool transaction events.
//!
//! Photon stores only the canonical, plaintext-free event. The optional
//! plaintext sidecar emitted by the dummy fixture is intentionally
//! NOT persisted here — it is consumed by the Zone RPC sidecar which owns the
//! private projection.

use crate::dao::generated::{
    shielded_nullifier_events, shielded_utxo_events, shielded_utxo_outputs, zone_configs,
};
use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::{
    ShieldedNullifierEventRecord, ShieldedOutputRecord, ShieldedTxEventRecord,
};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryTrait, Set,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::shielded_pool_events::{
        EncryptedTxEphemeralKey, EncryptedTxEphemeralKeyRole, ShieldedPoolTxKind,
        ShieldedPublicDelta,
    };
    use sea_orm::TransactionTrait;
    use sea_orm_migration::MigratorTrait;
    use solana_signature::Signature;

    async fn migrate_in_memory_db() -> sea_orm::DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        crate::migration::MigractorWithCustomMigrations::up(&db, None)
            .await
            .unwrap();
        db
    }

    fn sample_tx_event(slot: u64, event_index: u32) -> ShieldedTxEventRecord {
        ShieldedTxEventRecord {
            tx_signature: Signature::default(),
            event_index,
            slot,
            version: 1,
            instruction_tag: 1,
            tx_kind: ShieldedPoolTxKind::ProoflessShield,
            protocol_config: [7; 32],
            zone_config_hash: Some([9; 32]),
            tx_ephemeral_pubkey: [3; 32],
            encrypted_tx_ephemeral_keys: vec![EncryptedTxEphemeralKey {
                role: EncryptedTxEphemeralKeyRole::Auditor,
                key_id: 1,
                key_version: 1,
                hpke_ephemeral_pubkey: [4; 32],
                encrypted_tx_ephemeral_key: vec![0xaa; 48],
                auth_tag: [5; 16],
            }],
            operation_commitment: [6; 32],
            public_input_hash: None,
            utxo_public_inputs_hash: None,
            tree_public_inputs_hash: None,
            nullifier_chain: None,
            input_nullifiers: vec![],
            public_delta: ShieldedPublicDelta::default(),
            relayer_fee: None,
        }
    }

    fn sample_output(event_index: u32, output_index: u8, slot: u64) -> ShieldedOutputRecord {
        ShieldedOutputRecord {
            tx_signature: Signature::default(),
            event_index,
            output_index,
            slot,
            utxo_hash: [(event_index as u8).wrapping_add(output_index); 32],
            utxo_tree: None,
            leaf_index: None,
            tree_sequence: None,
            encrypted_utxo: vec![1, 2, 3, output_index],
            encrypted_utxo_hash: [output_index ^ 0xff; 32],
            fmd_clue: None,
            zone_config_hash: Some([9; 32]),
        }
    }

    #[tokio::test]
    async fn persists_one_event_with_two_outputs() {
        let db = migrate_in_memory_db().await;
        let txn = db.begin().await.unwrap();

        let tx_events = vec![sample_tx_event(100, 0)];
        let outputs = vec![sample_output(0, 0, 100), sample_output(0, 1, 100)];
        let zone_configs_seen = vec![([9u8; 32], 100u64)];

        persist_shielded_pool_state(&txn, &tx_events, &outputs, &[], &zone_configs_seen)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let events_in_db = shielded_utxo_events::Entity::find().all(&db).await.unwrap();
        assert_eq!(events_in_db.len(), 1);
        let outputs_in_db = shielded_utxo_outputs::Entity::find()
            .all(&db)
            .await
            .unwrap();
        assert_eq!(outputs_in_db.len(), 2);
        let zones_in_db = zone_configs::Entity::find().all(&db).await.unwrap();
        assert_eq!(zones_in_db.len(), 1);
    }

    #[tokio::test]
    async fn reindexing_same_event_is_idempotent() {
        let db = migrate_in_memory_db().await;

        let tx_events = vec![sample_tx_event(100, 0)];
        let outputs = vec![sample_output(0, 0, 100), sample_output(0, 1, 100)];
        let zone_configs_seen = vec![([9u8; 32], 100u64)];

        for _ in 0..3 {
            let txn = db.begin().await.unwrap();
            persist_shielded_pool_state(&txn, &tx_events, &outputs, &[], &zone_configs_seen)
                .await
                .unwrap();
            txn.commit().await.unwrap();
        }

        let events_in_db = shielded_utxo_events::Entity::find().all(&db).await.unwrap();
        assert_eq!(events_in_db.len(), 1);
        let outputs_in_db = shielded_utxo_outputs::Entity::find()
            .all(&db)
            .await
            .unwrap();
        assert_eq!(outputs_in_db.len(), 2);
    }

    #[tokio::test]
    async fn updates_zone_config_last_seen_slot_on_replay() {
        let db = migrate_in_memory_db().await;

        let txn = db.begin().await.unwrap();
        persist_shielded_pool_state(&txn, &[], &[], &[], &[([9u8; 32], 50)])
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let txn = db.begin().await.unwrap();
        persist_shielded_pool_state(&txn, &[], &[], &[], &[([9u8; 32], 200)])
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let zones_in_db = zone_configs::Entity::find().all(&db).await.unwrap();
        assert_eq!(zones_in_db.len(), 1);

        let txn = db.begin().await.unwrap();
        persist_shielded_pool_state(&txn, &[], &[], &[], &[([9u8; 32], 50)])
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let zones_in_db = zone_configs::Entity::find().all(&db).await.unwrap();
        assert_eq!(zones_in_db.len(), 1);
        assert_eq!(zones_in_db[0].first_seen_slot, 50);
        assert_eq!(zones_in_db[0].last_seen_slot, 200);
    }
}

/// Persist all shielded-pool data accumulated for one slot/transaction batch.
///
/// All inserts are idempotent: re-indexing the same `(tx_signature,
/// event_index)` is a no-op, which the plan calls out as a hard requirement.
pub async fn persist_shielded_pool_state(
    txn: &DatabaseTransaction,
    tx_events: &[ShieldedTxEventRecord],
    outputs: &[ShieldedOutputRecord],
    nullifier_events: &[ShieldedNullifierEventRecord],
    zone_configs_seen: &[([u8; 32], u64)],
) -> Result<(), IngesterError> {
    persist_zone_configs(txn, zone_configs_seen).await?;
    persist_tx_events(txn, tx_events).await?;
    persist_outputs(txn, outputs).await?;
    persist_nullifier_events(txn, nullifier_events).await?;
    Ok(())
}

async fn persist_zone_configs(
    txn: &DatabaseTransaction,
    zone_configs_seen: &[([u8; 32], u64)],
) -> Result<(), IngesterError> {
    if zone_configs_seen.is_empty() {
        return Ok(());
    }

    let models = zone_configs_seen
        .iter()
        .map(|(zone_hash, slot)| zone_configs::ActiveModel {
            zone_config_hash: Set(zone_hash.to_vec()),
            first_seen_slot: Set(*slot as i64),
            last_seen_slot: Set(*slot as i64),
            metadata: Set(None),
        })
        .collect::<Vec<_>>();

    // Insert first-seen rows idempotently, then advance last_seen_slot only
    // when the replayed slot is newer. This avoids backend-specific
    // GREATEST/EXCLUDED SQL and prevents old replays from regressing the row.
    let query = zone_configs::Entity::insert_many(models)
        .on_conflict(
            OnConflict::columns([zone_configs::Column::ZoneConfigHash])
                .do_nothing()
                .to_owned(),
        )
        .build(txn.get_database_backend());
    txn.execute(query).await?;

    for (zone_hash, slot) in zone_configs_seen {
        zone_configs::Entity::update_many()
            .col_expr(
                zone_configs::Column::LastSeenSlot,
                Expr::value(*slot as i64),
            )
            .filter(zone_configs::Column::ZoneConfigHash.eq(zone_hash.to_vec()))
            .filter(zone_configs::Column::LastSeenSlot.lt(*slot as i64))
            .exec(txn)
            .await?;
    }
    Ok(())
}

async fn persist_tx_events(
    txn: &DatabaseTransaction,
    tx_events: &[ShieldedTxEventRecord],
) -> Result<(), IngesterError> {
    if tx_events.is_empty() {
        return Ok(());
    }

    let models = tx_events
        .iter()
        .map(|event| shielded_utxo_events::ActiveModel {
            tx_signature: Set(Into::<[u8; 64]>::into(event.tx_signature).to_vec()),
            event_index: Set(event.event_index as i32),
            slot: Set(event.slot as i64),
            version: Set(event.version as i16),
            instruction_tag: Set(event.instruction_tag as i16),
            tx_kind: Set(event.tx_kind.clone() as i16),
            protocol_config: Set(event.protocol_config.to_vec()),
            zone_config_hash: Set(event.zone_config_hash.map(|h| h.to_vec())),
            tx_ephemeral_pubkey: Set(event.tx_ephemeral_pubkey.to_vec()),
            encrypted_tx_ephemeral_keys: Set(borsh::to_vec(&event.encrypted_tx_ephemeral_keys)
                .expect("encrypted_tx_ephemeral_keys borsh encode")),
            operation_commitment: Set(event.operation_commitment.to_vec()),
            public_inputs_hash: Set(event.public_input_hash.map(|h| h.to_vec())),
            utxo_public_inputs_hash: Set(event.utxo_public_inputs_hash.map(|h| h.to_vec())),
            tree_public_inputs_hash: Set(event.tree_public_inputs_hash.map(|h| h.to_vec())),
            nullifier_chain: Set(event.nullifier_chain.map(|h| h.to_vec())),
            input_nullifiers: Set(
                borsh::to_vec(&event.input_nullifiers).expect("input_nullifiers borsh encode")
            ),
            public_delta_mint: Set(event.public_delta.mint.map(|m| m.to_vec())),
            public_delta_spl: Set(event.public_delta.spl_amount.to_be_bytes().to_vec()),
            public_delta_sol: Set(event.public_delta.sol_amount.to_be_bytes().to_vec()),
            relayer_fee: Set(event.relayer_fee.map(|f| f as i64)),
        })
        .collect::<Vec<_>>();

    let query = shielded_utxo_events::Entity::insert_many(models)
        .on_conflict(
            OnConflict::columns([
                shielded_utxo_events::Column::TxSignature,
                shielded_utxo_events::Column::EventIndex,
            ])
            .do_nothing()
            .to_owned(),
        )
        .build(txn.get_database_backend());
    txn.execute(query).await?;
    Ok(())
}

async fn persist_outputs(
    txn: &DatabaseTransaction,
    outputs: &[ShieldedOutputRecord],
) -> Result<(), IngesterError> {
    if outputs.is_empty() {
        return Ok(());
    }

    let models = outputs
        .iter()
        .map(|out| shielded_utxo_outputs::ActiveModel {
            tx_signature: Set(Into::<[u8; 64]>::into(out.tx_signature).to_vec()),
            event_index: Set(out.event_index as i32),
            output_index: Set(out.output_index as i16),
            slot: Set(out.slot as i64),
            utxo_hash: Set(out.utxo_hash.to_vec()),
            utxo_tree: Set(out.utxo_tree.map(|t| t.to_vec())),
            leaf_index: Set(out.leaf_index.map(|i| i as i64)),
            tree_sequence: Set(out.tree_sequence.map(|s| s as i64)),
            encrypted_utxo: Set(out.encrypted_utxo.clone()),
            encrypted_utxo_hash: Set(out.encrypted_utxo_hash.to_vec()),
            fmd_clue: Set(out.fmd_clue.clone()),
            zone_config_hash: Set(out.zone_config_hash.map(|h| h.to_vec())),
        })
        .collect::<Vec<_>>();

    let query = shielded_utxo_outputs::Entity::insert_many(models)
        .on_conflict(
            OnConflict::columns([
                shielded_utxo_outputs::Column::TxSignature,
                shielded_utxo_outputs::Column::EventIndex,
                shielded_utxo_outputs::Column::OutputIndex,
            ])
            .do_nothing()
            .to_owned(),
        )
        .build(txn.get_database_backend());
    txn.execute(query).await?;
    Ok(())
}

async fn persist_nullifier_events(
    txn: &DatabaseTransaction,
    nullifier_events: &[ShieldedNullifierEventRecord],
) -> Result<(), IngesterError> {
    if nullifier_events.is_empty() {
        return Ok(());
    }

    let models = nullifier_events
        .iter()
        .map(|nf| shielded_nullifier_events::ActiveModel {
            nullifier: Set(nf.nullifier.to_vec()),
            nullifier_tree: Set(nf.nullifier_tree.to_vec()),
            tx_signature: Set(Into::<[u8; 64]>::into(nf.tx_signature).to_vec()),
            event_index: Set(nf.event_index as i32),
            slot: Set(nf.slot as i64),
        })
        .collect::<Vec<_>>();

    let query = shielded_nullifier_events::Entity::insert_many(models)
        .on_conflict(
            OnConflict::columns([shielded_nullifier_events::Column::Nullifier])
                .do_nothing()
                .to_owned(),
        )
        .build(txn.get_database_backend());
    txn.execute(query).await?;
    Ok(())
}
