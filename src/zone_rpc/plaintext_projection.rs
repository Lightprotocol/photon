//! Option B plaintext projection for the first Zone RPC prototype.
//!
//! The only accepted plaintext input in this milestone is the fixture-only
//! sidecar emitted by `shielded_pool_test_fixture`. Production decryption will
//! replace that input path, but the critical invariant stays the same:
//! `hash(plaintext) == shielded_utxo_outputs.utxo_hash` before any private row
//! is stored.
//!
//! This module is compiled only for tests or the `zone-rpc-prototype` feature.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use crate::ingester::parser::shielded_pool_events::{
    FixturePlaintextPayload, FixturePlaintextSidecar,
};
use crate::ingester::parser::shielded_pool_test_fixture::utxo_hash_for_payload;
use crate::ingester::parser::state_update::{
    ShieldedOutputRecord, ShieldedTxEventRecord, StateUpdate,
};
use crate::zone_rpc::types::ZoneDecryptedUtxoRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRpcProjectionConfig {
    pub zone_config_hash: [u8; 32],
    /// Must stay false outside local/dev tests. Real deployments should feed
    /// this projector with decrypted payloads from a TEE/auditor worker.
    pub allow_fixture_plaintext: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneRpcProjectionError {
    FixturePlaintextDisabled,
    OperationCommitmentNotFound([u8; 32]),
    MissingZoneConfigHash([u8; 32]),
    ZoneMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    PayloadOutputCountMismatch {
        payloads: usize,
        outputs: usize,
    },
    OutputNotFound {
        output_index: u8,
    },
    PlaintextZoneMismatch {
        output_index: u8,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    PlaintextHashMismatch {
        output_index: u8,
        expected_utxo_hash: [u8; 32],
        recomputed_utxo_hash: [u8; 32],
    },
    UtxoAlreadyExistsWithDifferentPayload([u8; 32]),
    HashError(String),
}

impl fmt::Display for ZoneRpcProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixturePlaintextDisabled => {
                write!(f, "fixture plaintext projection is disabled")
            }
            Self::OperationCommitmentNotFound(_) => {
                write!(f, "operation commitment was not found in Photon state")
            }
            Self::MissingZoneConfigHash(_) => {
                write!(f, "shielded event has no zone_config_hash")
            }
            Self::ZoneMismatch { .. } => write!(f, "shielded event belongs to a different zone"),
            Self::PayloadOutputCountMismatch { payloads, outputs } => write!(
                f,
                "plaintext payload count ({payloads}) does not match output count ({outputs})"
            ),
            Self::OutputNotFound { output_index } => {
                write!(f, "shielded output {output_index} was not found")
            }
            Self::PlaintextZoneMismatch { output_index, .. } => write!(
                f,
                "plaintext payload for output {output_index} belongs to a different zone"
            ),
            Self::PlaintextHashMismatch { output_index, .. } => write!(
                f,
                "plaintext payload for output {output_index} does not hash to utxo_hash"
            ),
            Self::UtxoAlreadyExistsWithDifferentPayload(_) => {
                write!(f, "utxo already exists with a different private payload")
            }
            Self::HashError(err) => write!(f, "failed to hash plaintext payload: {err}"),
        }
    }
}

impl Error for ZoneRpcProjectionError {}

pub struct ZonePlaintextProjector {
    config: ZoneRpcProjectionConfig,
}

impl ZonePlaintextProjector {
    pub fn new(config: ZoneRpcProjectionConfig) -> Self {
        Self { config }
    }

    pub fn project_fixture_sidecar(
        &self,
        state_update: &StateUpdate,
        sidecar: &FixturePlaintextSidecar,
    ) -> Result<Vec<ZoneDecryptedUtxoRecord>, ZoneRpcProjectionError> {
        if !self.config.allow_fixture_plaintext {
            return Err(ZoneRpcProjectionError::FixturePlaintextDisabled);
        }

        let event = state_update
            .shielded_tx_events
            .iter()
            .find(|event| event.operation_commitment == sidecar.operation_commitment)
            .ok_or(ZoneRpcProjectionError::OperationCommitmentNotFound(
                sidecar.operation_commitment,
            ))?;

        self.validate_event_zone(event)?;

        let outputs = state_update
            .shielded_outputs
            .iter()
            .filter(|output| {
                output.tx_signature == event.tx_signature && output.event_index == event.event_index
            })
            .collect::<Vec<_>>();

        if sidecar.payloads.len() != outputs.len() {
            return Err(ZoneRpcProjectionError::PayloadOutputCountMismatch {
                payloads: sidecar.payloads.len(),
                outputs: outputs.len(),
            });
        }

        sidecar
            .payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                let output_index = index as u8;
                let output = outputs
                    .iter()
                    .find(|output| output.output_index == output_index)
                    .ok_or(ZoneRpcProjectionError::OutputNotFound { output_index })?;
                self.project_payload(event, output, payload)
            })
            .collect()
    }

    fn validate_event_zone(
        &self,
        event: &ShieldedTxEventRecord,
    ) -> Result<(), ZoneRpcProjectionError> {
        let actual =
            event
                .zone_config_hash
                .ok_or(ZoneRpcProjectionError::MissingZoneConfigHash(
                    event.operation_commitment,
                ))?;
        if actual != self.config.zone_config_hash {
            return Err(ZoneRpcProjectionError::ZoneMismatch {
                expected: self.config.zone_config_hash,
                actual,
            });
        }
        Ok(())
    }

    fn project_payload(
        &self,
        event: &ShieldedTxEventRecord,
        output: &ShieldedOutputRecord,
        payload: &FixturePlaintextPayload,
    ) -> Result<ZoneDecryptedUtxoRecord, ZoneRpcProjectionError> {
        if payload.zone_config_hash != self.config.zone_config_hash {
            return Err(ZoneRpcProjectionError::PlaintextZoneMismatch {
                output_index: output.output_index,
                expected: self.config.zone_config_hash,
                actual: payload.zone_config_hash,
            });
        }

        let recomputed =
            utxo_hash_for_payload(payload).map_err(ZoneRpcProjectionError::HashError)?;
        if recomputed != output.utxo_hash {
            return Err(ZoneRpcProjectionError::PlaintextHashMismatch {
                output_index: output.output_index,
                expected_utxo_hash: output.utxo_hash,
                recomputed_utxo_hash: recomputed,
            });
        }

        Ok(ZoneDecryptedUtxoRecord {
            utxo_hash: output.utxo_hash,
            operation_commitment: event.operation_commitment,
            zone_config_hash: self.config.zone_config_hash,
            owner_pubkey: payload.owner_pubkey,
            owner_hash: payload.owner_hash,
            token_mint: payload.token_mint,
            spl_amount: payload.spl_amount,
            sol_amount: payload.sol_amount,
            data_hash: payload.data_hash,
            slot: output.slot,
            signature: output.tx_signature,
            event_index: output.event_index,
            output_index: output.output_index,
            leaf_index: output.leaf_index,
            tree_sequence: output.tree_sequence,
            spent: false,
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryZonePrivateStore {
    rows_by_utxo_hash: HashMap<[u8; 32], ZoneDecryptedUtxoRecord>,
}

impl InMemoryZonePrivateStore {
    pub fn upsert_many(
        &mut self,
        rows: impl IntoIterator<Item = ZoneDecryptedUtxoRecord>,
    ) -> Result<(), ZoneRpcProjectionError> {
        for row in rows {
            self.upsert(row)?;
        }
        Ok(())
    }

    pub fn upsert(&mut self, row: ZoneDecryptedUtxoRecord) -> Result<(), ZoneRpcProjectionError> {
        if let Some(existing) = self.rows_by_utxo_hash.get(&row.utxo_hash) {
            if existing != &row {
                return Err(
                    ZoneRpcProjectionError::UtxoAlreadyExistsWithDifferentPayload(row.utxo_hash),
                );
            }
            return Ok(());
        }
        self.rows_by_utxo_hash.insert(row.utxo_hash, row);
        Ok(())
    }

    pub fn fetch_decrypted_utxos_by_owner_hash(
        &self,
        zone_config_hash: [u8; 32],
        owner_hash: [u8; 32],
        include_spent: bool,
    ) -> Vec<ZoneDecryptedUtxoRecord> {
        let mut rows = self
            .rows_by_utxo_hash
            .values()
            .filter(|row| {
                row.zone_config_hash == zone_config_hash
                    && row.owner_hash == owner_hash
                    && (include_spent || !row.spent)
            })
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            b.slot
                .cmp(&a.slot)
                .then(a.event_index.cmp(&b.event_index))
                .then(a.output_index.cmp(&b.output_index))
        });
        rows
    }

    pub fn fetch_decrypted_utxos_by_owner_pubkey(
        &self,
        zone_config_hash: [u8; 32],
        owner_pubkey: [u8; 32],
        include_spent: bool,
    ) -> Vec<ZoneDecryptedUtxoRecord> {
        let mut rows = self
            .rows_by_utxo_hash
            .values()
            .filter(|row| {
                row.zone_config_hash == zone_config_hash
                    && row.owner_pubkey == owner_pubkey
                    && (include_spent || !row.spent)
            })
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            b.slot
                .cmp(&a.slot)
                .then(a.event_index.cmp(&b.event_index))
                .then(a.output_index.cmp(&b.output_index))
        });
        rows
    }

    pub fn mark_spent(&mut self, utxo_hash: [u8; 32]) -> bool {
        match self.rows_by_utxo_hash.get_mut(&utxo_hash) {
            Some(row) => {
                row.spent = true;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::shielded_pool_test_fixture::{
        DummyShieldedPoolFixture, FixtureBuilder, FixtureOwnerSpec,
    };
    use crate::ingester::parser::{
        shielded_pool_event_parser::parse_shielded_pool_events, SHIELDED_POOL_PROGRAM_ID,
    };
    use solana_signature::Signature;

    fn fixture() -> DummyShieldedPoolFixture {
        let owner = FixtureOwnerSpec {
            owner_pubkey: [0xAA; 32],
            token_mint: [0xBB; 32],
            spl_amount: 1_000_000,
            sol_amount: 42,
            blinding: [0xCC; 32],
        };
        FixtureBuilder::proofless_shield_one_output(Signature::default(), owner).build()
    }

    fn parse_fixture(fixture: &DummyShieldedPoolFixture) -> StateUpdate {
        let group = &fixture.transaction_info.instruction_groups[0];
        parse_shielded_pool_events(
            group,
            fixture.transaction_info.signature,
            100,
            &[SHIELDED_POOL_PROGRAM_ID],
        )
    }

    fn projector(zone_config_hash: [u8; 32]) -> ZonePlaintextProjector {
        ZonePlaintextProjector::new(ZoneRpcProjectionConfig {
            zone_config_hash,
            allow_fixture_plaintext: true,
        })
    }

    #[test]
    fn projects_fixture_plaintext_into_private_rows() {
        let fixture = fixture();
        let state_update = parse_fixture(&fixture);
        let zone = fixture.event.zone_config_hash.unwrap();

        let rows = projector(zone)
            .project_fixture_sidecar(&state_update, &fixture.sidecar)
            .expect("project sidecar");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].utxo_hash, fixture.event.outputs[0].utxo_hash);
        assert_eq!(rows[0].owner_hash, fixture.sidecar.payloads[0].owner_hash);
        assert_eq!(rows[0].spl_amount, 1_000_000);
        assert_eq!(rows[0].sol_amount, 42);
        assert!(!rows[0].spent);
    }

    #[test]
    fn stores_and_fetches_by_owner_hash() {
        let fixture = fixture();
        let state_update = parse_fixture(&fixture);
        let zone = fixture.event.zone_config_hash.unwrap();
        let rows = projector(zone)
            .project_fixture_sidecar(&state_update, &fixture.sidecar)
            .unwrap();

        let owner_hash = fixture.sidecar.payloads[0].owner_hash;
        let mut store = InMemoryZonePrivateStore::default();
        store.upsert_many(rows.clone()).unwrap();
        store.upsert_many(rows).unwrap();

        let fetched = store.fetch_decrypted_utxos_by_owner_hash(zone, owner_hash, false);
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].utxo_hash, fixture.event.outputs[0].utxo_hash);
    }

    #[test]
    fn spent_rows_are_hidden_by_default() {
        let fixture = fixture();
        let state_update = parse_fixture(&fixture);
        let zone = fixture.event.zone_config_hash.unwrap();
        let rows = projector(zone)
            .project_fixture_sidecar(&state_update, &fixture.sidecar)
            .unwrap();
        let owner_hash = fixture.sidecar.payloads[0].owner_hash;

        let mut store = InMemoryZonePrivateStore::default();
        store.upsert_many(rows).unwrap();
        assert!(store.mark_spent(fixture.event.outputs[0].utxo_hash));

        assert!(store
            .fetch_decrypted_utxos_by_owner_hash(zone, owner_hash, false)
            .is_empty());
        assert_eq!(
            store
                .fetch_decrypted_utxos_by_owner_hash(zone, owner_hash, true)
                .len(),
            1
        );
    }

    #[test]
    fn rejects_wrong_zone() {
        let fixture = fixture();
        let state_update = parse_fixture(&fixture);
        let err = projector([0x55; 32])
            .project_fixture_sidecar(&state_update, &fixture.sidecar)
            .unwrap_err();
        assert!(matches!(err, ZoneRpcProjectionError::ZoneMismatch { .. }));
    }

    #[test]
    fn rejects_tampered_plaintext() {
        let fixture = fixture();
        let state_update = parse_fixture(&fixture);
        let zone = fixture.event.zone_config_hash.unwrap();
        let mut sidecar = fixture.sidecar.clone();
        sidecar.payloads[0].spl_amount += 1;

        let err = projector(zone)
            .project_fixture_sidecar(&state_update, &sidecar)
            .unwrap_err();
        assert!(matches!(
            err,
            ZoneRpcProjectionError::PlaintextHashMismatch { .. }
        ));
    }

    #[test]
    fn fixture_plaintext_is_disabled_by_default() {
        let fixture = fixture();
        let state_update = parse_fixture(&fixture);
        let zone = fixture.event.zone_config_hash.unwrap();
        let projector = ZonePlaintextProjector::new(ZoneRpcProjectionConfig {
            zone_config_hash: zone,
            allow_fixture_plaintext: false,
        });

        let err = projector
            .project_fixture_sidecar(&state_update, &fixture.sidecar)
            .unwrap_err();
        assert_eq!(err, ZoneRpcProjectionError::FixturePlaintextDisabled);
    }
}
