use crate::api::error::PhotonApiError;
use crate::api::method::utils::{parse_decimal, parse_discriminator_string};
use crate::common::typedefs::bs64_string::Base64String;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::unsigned_integer::UnsignedInteger;
use crate::dao::generated::accounts::Model;
use jsonrpsee_core::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Account {
    pub hash: Hash,
    pub address: Option<SerializablePubkey>,
    pub data: Option<AccountData>,
    pub owner: SerializablePubkey,
    pub lamports: UnsignedInteger,
    pub tree: SerializablePubkey,
    pub leaf_index: UnsignedInteger,
    // For V1 trees is always Some() since the user tx appends directly to the Merkle tree
    // for V2 batched trees:
    // 2.1. None when is in output queue
    // 2.2. Some once it was inserted into the Merkle tree from the output queue
    pub seq: Option<UnsignedInteger>,
    pub slot_created: UnsignedInteger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccountData {
    #[serde(serialize_with = "serialize_discriminator_as_string")]
    pub discriminator: UnsignedInteger,
    pub data: Base64String,
    pub data_hash: Hash,
}

// Fixes precision loss.
fn serialize_discriminator_as_string<S>(
    discriminator: &UnsignedInteger,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let discriminator_string = discriminator.0.to_string();
    serializer.serialize_str(&discriminator_string)
}

impl TryFrom<Model> for Account {
    type Error = PhotonApiError;

    fn try_from(account: Model) -> Result<Self, Self::Error> {
        let data = match (account.data, account.data_hash, account.discriminator) {
            (Some(data), Some(data_hash), Some(discriminator)) => Some(AccountData {
                data: Base64String(data),
                data_hash: data_hash.try_into()?,
                discriminator: UnsignedInteger(parse_discriminator_string(discriminator)?),
            }),
            (None, None, None) => None,
            _ => {
                return Err(PhotonApiError::UnexpectedError(
                    "Invalid account data".to_string(),
                ))
            }
        };

        Ok(Account {
            hash: account.hash.try_into()?,
            address: account
                .address
                .map(SerializablePubkey::try_from)
                .transpose()?,
            data,
            owner: account.owner.try_into()?,
            tree: account.tree.try_into()?,
            leaf_index: UnsignedInteger(crate::api::method::utils::parse_leaf_index(
                account.leaf_index,
            )?),
            lamports: UnsignedInteger(parse_decimal(account.lamports)?),
            slot_created: UnsignedInteger(account.slot_created as u64),
            seq: account.seq.map(|seq| UnsignedInteger(seq as u64)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminator_serializes_as_string() {
        // Test the discriminator value from the original precision loss issue
        let bytes = [247u8, 237, 227, 245, 215, 195, 222, 70];
        let expected_u64 = u64::from_le_bytes(bytes);

        let account_data = AccountData {
            discriminator: UnsignedInteger(expected_u64),
            data: Base64String(vec![1, 2, 3]),
            data_hash: Hash::default(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&account_data).unwrap();

        // Verify discriminator is serialized as a string, not a number
        assert!(
            json.contains(&format!("\"discriminator\":\"{}\"", expected_u64)),
            "Discriminator should be serialized as string, got: {}",
            json
        );

        // Verify it doesn't contain the number format
        assert!(
            !json.contains(&format!("\"discriminator\":{}", expected_u64)),
            "Discriminator should not be serialized as number, got: {}",
            json
        );
    }

    #[test]
    fn test_discriminator_prevents_javascript_precision_loss() {
        // Test with a value that exceeds JavaScript's MAX_SAFE_INTEGER
        let large_discriminator = 9007199254740992u64; // MAX_SAFE_INTEGER + 1

        let account_data = AccountData {
            discriminator: UnsignedInteger(large_discriminator),
            data: Base64String(vec![]),
            data_hash: Hash::default(),
        };

        let json = serde_json::to_string(&account_data).unwrap();

        // Should be serialized as string
        assert!(
            json.contains(&format!("\"discriminator\":\"{}\"", large_discriminator)),
            "Large discriminator should be serialized as string to prevent JS precision loss, got: {}",
            json
        );
    }

    #[test]
    fn test_discriminator_with_max_u64() {
        // Test with u64::MAX
        let max_discriminator = u64::MAX;

        let account_data = AccountData {
            discriminator: UnsignedInteger(max_discriminator),
            data: Base64String(vec![]),
            data_hash: Hash::default(),
        };

        let json = serde_json::to_string(&account_data).unwrap();

        // Should be serialized as string
        assert!(
            json.contains(&format!("\"discriminator\":\"{}\"", max_discriminator)),
            "MAX u64 discriminator should be serialized as string, got: {}",
            json
        );
    }

    #[test]
    fn test_discriminator_zero_value() {
        // Test with zero value
        let account_data = AccountData {
            discriminator: UnsignedInteger(0),
            data: Base64String(vec![]),
            data_hash: Hash::default(),
        };

        let json = serde_json::to_string(&account_data).unwrap();

        // Should be serialized as string "0"
        assert!(
            json.contains("\"discriminator\":\"0\""),
            "Zero discriminator should be serialized as string, got: {}",
            json
        );
    }
}
