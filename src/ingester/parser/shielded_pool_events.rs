//! Borsh shapes for the zoned shielded-pool event family that the future
//! shielded-pool program emits via Noop CPI. The first vertical slice uses a
//! test-only emitter that produces these exact bytes; once the real program
//! is wired, the format does not change.
//!
//! The canonical event holds only ciphertext and public commitments. Plaintext
//! UTXO payloads exist only for dev/test fixtures behind the
//! `shielded-fixtures` feature. They are explicitly never persisted into
//! Photon public tables nor returned through Photon public APIs.

use borsh::{BorshDeserialize, BorshSerialize};

/// First-version discriminator. ASCII "shldplv1" (shielded pool v1). Any Noop
/// CPI whose data does not start with these eight bytes is not a shielded-pool
/// event, so the parser can scan instructions without worrying about
/// false-positive borsh decodes.
pub const SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR: [u8; 8] =
    [b's', b'h', b'l', b'd', b'p', b'l', b'v', b'1'];

/// Current event version. Incremented in lockstep with the on-chain program;
/// the parser refuses to deserialize newer versions until the parser is
/// updated, but a malformed/unknown-version event must not stop unrelated
/// indexing.
pub const SHIELDED_POOL_TX_EVENT_VERSION: u8 = 1;

/// What kind of shielded-pool transition this event encodes. The `tx_kind`
/// drives how the on-chain verifier processes public deltas, fees, and zone
/// authority paths; Photon stores it as-is so consumers can filter without
/// re-parsing the operation commitment.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ShieldedPoolTxKind {
    /// Public deposit into a UTXO without a UTXO proof. Public_delta carries
    /// the deposit amount; outputs are still encrypted.
    ProoflessShield = 0,
    /// Standard shielded transact (UtxoProof + TreeProof).
    Transact = 1,
    /// Zoned transact: same proofs plus zone-config binding and zone fees.
    ZoneTransact = 2,
    /// Zone authority transition (e.g. freeze/unfreeze).
    ZoneAuthorityTransact = 3,
}

/// Role of an encrypted transaction-ephemeral-key recipient. The same
/// `tx_ephemeral_pubkey` is shared across outputs; this struct is the
/// envelope that delivers the matching ephemeral private material to each
/// participant or auditor under their long-term key.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptedTxEphemeralKeyRole {
    Auditor = 0,
    Sender = 1,
    Recipient = 2,
    /// Reserved for future viewing-key roles required by the protocol.
    ProtocolAuxiliary = 3,
}

/// Per-recipient envelope for the transaction ephemeral key. The plan locks
/// the encryption to ECDH + AES-GCM with one ephemeral key per transaction
/// shared across outputs, so this carries an HPKE-style ephemeral pubkey, a
/// key id/version for rotation, and the AES-GCM ciphertext + tag of the
/// transaction ephemeral material.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncryptedTxEphemeralKey {
    pub role: EncryptedTxEphemeralKeyRole,
    pub key_id: u32,
    pub key_version: u32,
    pub hpke_ephemeral_pubkey: [u8; 32],
    pub encrypted_tx_ephemeral_key: Vec<u8>,
    pub auth_tag: [u8; 16],
}

/// Public-side amount delta carried by shield/unshield/relayer flows. The
/// caller signs i128 amounts so withdrawals (negative net flow) and deposits
/// (positive) share one shape. `mint` is `None` for native SOL deltas.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ShieldedPublicDelta {
    pub mint: Option<[u8; 32]>,
    pub spl_amount: i128,
    pub sol_amount: i128,
}

/// One created UTXO. Fields that depend on the real append path
/// (`utxo_tree`, `leaf_index`, `tree_sequence`) are nullable so
/// dummy events can be emitted before the compressed-account program is
/// wired.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ShieldedUtxoOutputEvent {
    pub output_index: u8,
    pub utxo_hash: [u8; 32],
    pub utxo_tree: Option<[u8; 32]>,
    pub leaf_index: Option<u64>,
    pub tree_sequence: Option<u64>,
    pub encrypted_utxo: Vec<u8>,
    pub encrypted_utxo_hash: [u8; 32],
    pub fmd_clue: Option<Vec<u8>>,
}

/// Top-level shielded-pool transaction event. One event per shielded
/// operation; multiple events may exist per Solana transaction
/// (`tx_event_index` orders them).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ShieldedPoolTxEvent {
    /// Constant 8-byte discriminator that lets the parser scan Noop CPIs
    /// without false-positive borsh decodes against unrelated payloads.
    pub event_discriminator: [u8; 8],
    pub version: u8,
    pub tx_event_index: u32,
    /// Identifies the shielded-pool instruction that emitted this event.
    /// Useful for parser-side observability and for distinguishing variants
    /// of the same `tx_kind`.
    pub instruction_tag: u8,
    pub tx_kind: ShieldedPoolTxKind,
    /// 32-byte protocol config hash. Lets indexers correlate events with the
    /// configuration they were validated under without storing the full
    /// config inline.
    pub protocol_config: [u8; 32],
    /// Public in the prototype/public-zone mode. Once auditor-key boxes
    /// gate zone visibility, this becomes `None` for events whose
    /// zone is private.
    pub zone_config_hash: Option<[u8; 32]>,
    pub tx_ephemeral_pubkey: [u8; 32],
    pub encrypted_tx_ephemeral_keys: Vec<EncryptedTxEphemeralKey>,
    /// `operation_commitment` = the user-signed binding over the operation
    /// inputs (nullifiers, output hashes, ciphertext hashes, public deltas,
    /// expiry, zone context). Always present.
    pub operation_commitment: [u8; 32],
    /// Top-level Groth16 public-input hash for the bundled proof. `None`
    /// before the proof path is wired.
    pub public_input_hash: Option<[u8; 32]>,
    /// MASP-circuit-aligned per-proof public-input hashes. `None` until the
    /// shielded-pool program emits real proofs; the parser persists them
    /// when present so the verifier can recompute via the published preimage.
    pub utxo_public_inputs_hash: Option<[u8; 32]>,
    pub tree_public_inputs_hash: Option<[u8; 32]>,
    /// Cached `HashChain(input_nullifiers)` shared between UtxoProof and
    /// TreeProof. The parser may recompute this from `input_nullifiers` in
    /// public-zone mode; once private-zone proofs ship, recomputation may
    /// require auditor-key access and storing the cached chain saves work.
    pub nullifier_chain: Option<[u8; 32]>,
    pub input_nullifiers: Vec<[u8; 32]>,
    pub public_delta: ShieldedPublicDelta,
    pub relayer_fee: Option<u64>,
    pub outputs: Vec<ShieldedUtxoOutputEvent>,
}

impl ShieldedPoolTxEvent {
    /// True when the prefix matches the v1 discriminator. Used by the parser
    /// to short-circuit before attempting a full borsh decode.
    pub fn matches_discriminator(data: &[u8]) -> bool {
        data.len() >= SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR.len()
            && data[..SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR.len()]
                == SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR
    }

    /// Build a borsh blob ready for a Noop CPI. Validates the version and
    /// discriminator so emitters cannot accidentally publish off-format
    /// bytes.
    pub fn to_event_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        if self.event_discriminator != SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "event_discriminator must equal SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR",
            ));
        }
        if self.version != SHIELDED_POOL_TX_EVENT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported shielded-pool tx event version",
            ));
        }
        borsh::to_vec(self)
    }

    /// Decode the v1 wire format. Caller is responsible for matching the
    /// discriminator first via `matches_discriminator`.
    pub fn from_event_bytes(data: &[u8]) -> Result<Self, std::io::Error> {
        let event = ShieldedPoolTxEvent::try_from_slice(data)?;
        if event.event_discriminator != SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "event_discriminator mismatch",
            ));
        }
        if event.version != SHIELDED_POOL_TX_EVENT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported shielded-pool tx event version",
            ));
        }
        Ok(event)
    }
}

/// On-chain spend event for an existing UTXO. The first milestone does not
/// emit these but the shape is fixed now so persistence and
/// API code can reference it.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ShieldedNullifierEvent {
    pub event_discriminator: [u8; 8],
    pub version: u8,
    pub nullifier: [u8; 32],
    pub nullifier_tree: [u8; 32],
    /// `tx_signature_index` lets the persistence layer link a nullifier back
    /// to the transaction event that consumed it.
    pub tx_event_index: u32,
}

/// **Test-fixture only.** Plaintext payload sidecar that mirrors the
/// canonical UTXO content. Production event emitters MUST NOT include this;
/// it exists so the dummy emitter can hand Zone RPC something to
/// project into `zone_decrypted_utxos` without going through real auditor
/// decryption. Photon must never persist this into public tables nor return
/// it through public APIs (see parser rules).
#[cfg(any(test, feature = "shielded-fixtures"))]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FixturePlaintextPayload {
    pub domain: u8,
    pub owner_pubkey: [u8; 32],
    pub owner_hash: [u8; 32],
    pub token_mint: [u8; 32],
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub extended_data: Vec<u8>,
    pub zone_config_hash: [u8; 32],
}

/// Sidecar bundle keyed by the operation commitment of the canonical event it
/// accompanies. One entry per output. Lives outside the main event so the
/// canonical event shape stays plaintext-free.
#[cfg(any(test, feature = "shielded-fixtures"))]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FixturePlaintextSidecar {
    pub operation_commitment: [u8; 32],
    pub payloads: Vec<FixturePlaintextPayload>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_output(index: u8) -> ShieldedUtxoOutputEvent {
        ShieldedUtxoOutputEvent {
            output_index: index,
            utxo_hash: [index; 32],
            utxo_tree: None,
            leaf_index: None,
            tree_sequence: None,
            encrypted_utxo: vec![1, 2, 3, index],
            encrypted_utxo_hash: [index ^ 0xff; 32],
            fmd_clue: None,
        }
    }

    fn sample_event() -> ShieldedPoolTxEvent {
        ShieldedPoolTxEvent {
            event_discriminator: SHIELDED_POOL_TX_EVENT_V1_DISCRIMINATOR,
            version: SHIELDED_POOL_TX_EVENT_VERSION,
            tx_event_index: 0,
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
            outputs: vec![sample_output(0)],
        }
    }

    #[test]
    fn round_trip_v1_event() {
        let event = sample_event();
        let bytes = event.to_event_bytes().expect("encode");
        assert!(ShieldedPoolTxEvent::matches_discriminator(&bytes));
        let decoded = ShieldedPoolTxEvent::from_event_bytes(&bytes).expect("decode");
        assert_eq!(event, decoded);
    }

    #[test]
    fn rejects_wrong_discriminator() {
        let mut event = sample_event();
        event.event_discriminator = [0; 8];
        assert!(event.to_event_bytes().is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        let mut event = sample_event();
        event.version = 99;
        assert!(event.to_event_bytes().is_err());
    }

    #[test]
    fn matches_discriminator_handles_short_input() {
        assert!(!ShieldedPoolTxEvent::matches_discriminator(&[]));
        assert!(!ShieldedPoolTxEvent::matches_discriminator(&[1, 2, 3]));
    }

    #[test]
    fn fixture_payload_round_trip() {
        let payload = FixturePlaintextPayload {
            domain: 1,
            owner_pubkey: [11; 32],
            owner_hash: [12; 32],
            token_mint: [13; 32],
            spl_amount: 1_000_000,
            sol_amount: 2_000_000,
            blinding: [14; 32],
            data_hash: [15; 32],
            extended_data: vec![],
            zone_config_hash: [16; 32],
        };
        let sidecar = FixturePlaintextSidecar {
            operation_commitment: [17; 32],
            payloads: vec![payload.clone()],
        };
        let bytes = borsh::to_vec(&sidecar).unwrap();
        let decoded = FixturePlaintextSidecar::try_from_slice(&bytes).unwrap();
        assert_eq!(decoded.payloads.len(), 1);
        assert_eq!(decoded.payloads[0], payload);
    }
}
