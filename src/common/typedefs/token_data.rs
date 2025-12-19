use borsh::{BorshDeserialize, BorshSerialize};
use num_enum::TryFromPrimitive;
use serde::Serialize;
use utoipa::ToSchema;

use super::{serializable_pubkey::SerializablePubkey, unsigned_integer::UnsignedInteger};

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
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

/// CompressedOnly extension for compressed token accounts
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    BorshDeserialize,
    BorshSerialize,
    ToSchema,
    Serialize,
)]
#[serde(rename_all = "camelCase")]
pub struct CompressedOnlyExtension {
    pub delegated_amount: u64,
    pub withheld_transfer_fee: u64,
}

/// Additional metadata key-value pair
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, ToSchema, Serialize)]
pub struct AdditionalMetadata {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Token metadata extension
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, ToSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenMetadata {
    pub update_authority: SerializablePubkey,
    pub mint: SerializablePubkey,
    pub name: Vec<u8>,
    pub symbol: Vec<u8>,
    pub uri: Vec<u8>,
    pub additional_metadata: Vec<AdditionalMetadata>,
}

/// Extension types for compressed token accounts.
/// Discriminants match Token-2022 extension type indices to maintain compatibility.
#[derive(Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, ToSchema, Serialize)]
#[serde(rename_all = "camelCase")]
#[repr(u8)]
pub enum ExtensionStruct {
    Placeholder0 = 0,
    Placeholder1 = 1,
    Placeholder2 = 2,
    Placeholder3 = 3,
    Placeholder4 = 4,
    Placeholder5 = 5,
    Placeholder6 = 6,
    Placeholder7 = 7,
    Placeholder8 = 8,
    Placeholder9 = 9,
    Placeholder10 = 10,
    Placeholder11 = 11,
    Placeholder12 = 12,
    Placeholder13 = 13,
    Placeholder14 = 14,
    Placeholder15 = 15,
    Placeholder16 = 16,
    Placeholder17 = 17,
    Placeholder18 = 18,
    TokenMetadata(TokenMetadata) = 19,
    Placeholder20 = 20,
    Placeholder21 = 21,
    Placeholder22 = 22,
    Placeholder23 = 23,
    Placeholder24 = 24,
    Placeholder25 = 25,
    Placeholder26 = 26,
    Placeholder27 = 27,
    Placeholder28 = 28,
    Placeholder29 = 29,
    Placeholder30 = 30,
    CompressedOnly(CompressedOnlyExtension) = 31,
    Placeholder32 = 32,
}

/// Custom serde serialization for tlv field to maintain API backward compatibility.
/// Serializes Vec<ExtensionStruct> to base64 string in JSON responses.
mod tlv_serde {
    use super::ExtensionStruct;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use borsh::BorshSerialize;
    use serde::Serializer;

    pub fn serialize<S>(
        value: &Option<Vec<ExtensionStruct>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(extensions) => {
                let bytes = extensions.try_to_vec().map_err(serde::ser::Error::custom)?;
                let base64_str = STANDARD.encode(&bytes);
                serializer.serialize_some(&base64_str)
            }
            None => serializer.serialize_none(),
        }
    }
}

#[derive(
    Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Clone, ToSchema, Serialize, Default,
)]
#[serde(rename_all = "camelCase")]
pub struct TokenData {
    /// The mint associated with this account
    pub mint: SerializablePubkey,
    /// The owner of this account.
    pub owner: SerializablePubkey,
    /// The amount of tokens this account holds.
    pub amount: UnsignedInteger,
    /// If `delegate` is `Some` then `delegated_amount` represents
    /// the amount authorized by the delegate
    pub delegate: Option<SerializablePubkey>,
    /// The account's state
    pub state: AccountState,
    /// Token extensions for compressed token accounts (serialized as base64 in API)
    #[serde(serialize_with = "tlv_serde::serialize")]
    pub tlv: Option<Vec<ExtensionStruct>>,
}
