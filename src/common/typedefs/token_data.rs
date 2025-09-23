use anchor_lang::{AnchorDeserialize, AnchorSerialize};
use num_enum::TryFromPrimitive;
use serde::Serialize;
use utoipa::ToSchema;

use super::{
    bs64_string::Base64String, serializable_pubkey::SerializablePubkey,
    unsigned_integer::{serialize_u64_as_string, UnsignedInteger},
};

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    AnchorSerialize,
    AnchorDeserialize,
    TryFromPrimitive,
    ToSchema,
    Serialize,
)]
#[repr(u8)]
#[derive(Default)]
pub enum AccountState {
    #[allow(non_camel_case_types)]
    #[default]
    initialized,
    #[allow(non_camel_case_types)]
    frozen,
}

#[derive(
    Debug, PartialEq, Eq, AnchorDeserialize, AnchorSerialize, Clone, ToSchema, Serialize, Default,
)]
#[serde(rename_all = "camelCase")]
pub struct TokenData {
    /// The mint associated with this account
    pub mint: SerializablePubkey,
    /// The owner of this account.
    pub owner: SerializablePubkey,
    /// The amount of tokens this account holds.
    #[serde(serialize_with = "serialize_u64_as_string")]
    pub amount: UnsignedInteger,
    /// If `delegate` is `Some` then `delegated_amount` represents
    /// the amount authorized by the delegate
    pub delegate: Option<SerializablePubkey>,
    /// The account's state
    pub state: AccountState,
    /// Placeholder for TokenExtension tlv data (unimplemented)
    pub tlv: Option<Base64String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_amount_serializes_as_string() {
        let token_data = TokenData {
            mint: SerializablePubkey::default(),
            owner: SerializablePubkey::default(),
            amount: UnsignedInteger(1000000000),
            delegate: None,
            state: AccountState::initialized,
            tlv: None,
        };

        let json = serde_json::to_string(&token_data).unwrap();

        assert!(
            json.contains("\"amount\":\"1000000000\""),
            "Amount should be serialized as string, got: {}",
            json
        );
    }

    #[test]
    fn test_token_amount_prevents_javascript_precision_loss() {
        let large_amount = u64::MAX;

        let token_data = TokenData {
            mint: SerializablePubkey::default(),
            owner: SerializablePubkey::default(),
            amount: UnsignedInteger(large_amount),
            delegate: None,
            state: AccountState::initialized,
            tlv: None,
        };

        let json = serde_json::to_string(&token_data).unwrap();

        assert!(
            json.contains(&format!("\"amount\":\"{}\"", large_amount)),
            "Large amount should be serialized as string to prevent JS precision loss, got: {}",
            json
        );
    }

    #[test]
    fn test_token_amount_zero_value() {
        let token_data = TokenData {
            mint: SerializablePubkey::default(),
            owner: SerializablePubkey::default(),
            amount: UnsignedInteger(0),
            delegate: None,
            state: AccountState::initialized,
            tlv: None,
        };

        let json = serde_json::to_string(&token_data).unwrap();

        assert!(
            json.contains("\"amount\":\"0\""),
            "Zero amount should be serialized as string, got: {}",
            json
        );
    }
}
