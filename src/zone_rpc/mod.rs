//! Zone RPC sidecar prototype behind the `zone-rpc-prototype` feature.
//!
//! This module intentionally lives outside the public Photon API path. Photon
//! owns canonical encrypted/public state; Zone RPC owns private projections
//! derived from auditor-visible plaintext or decrypted payloads. Do not enable
//! this feature for production Photon binaries; the production sidecar should
//! move into its own crate/process with a private database.

pub mod plaintext_projection;
pub mod private_api;
pub mod private_db;
pub mod types;
pub mod workers;
