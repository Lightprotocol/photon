use byteorder::{ByteOrder, LittleEndian};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::typedefs::bs58_string::Base58String;
use crate::common::typedefs::context::Context;
use crate::common::typedefs::limit::Limit;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::unsigned_integer::UnsignedInteger;
use crate::dao::generated::token_owner_balances;

use super::super::error::PhotonApiError;
use super::utils::{
    is_sqlite, parse_balance_string, parse_decimal, OwnerBalanceModel, OwnerBalanceModelString,
    PAGE_LIMIT,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OwnerBalance {
    pub owner: SerializablePubkey,
    pub balance: UnsignedInteger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OwnerBalanceList {
    pub items: Vec<OwnerBalance>,
    pub cursor: Option<Base58String>,
}

// We do not use generics to simplify documentation generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OwnerBalancesResponse {
    pub context: Context,
    pub value: OwnerBalanceList,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetCompressedMintTokenHoldersRequest {
    pub mint: SerializablePubkey,
    pub cursor: Option<Base58String>,
    pub limit: Option<Limit>,
}

pub async fn get_compressed_mint_token_holders(
    conn: &DatabaseConnection,
    request: GetCompressedMintTokenHoldersRequest,
) -> Result<OwnerBalancesResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let GetCompressedMintTokenHoldersRequest {
        mint,
        cursor,
        limit,
    } = request;
    let mut filter = token_owner_balances::Column::Mint.eq::<Vec<u8>>(mint.into());

    if let Some(cursor) = cursor {
        let bytes = cursor.0;
        let expected_cursor_length = 40;
        let (balance, owner) = if bytes.len() == expected_cursor_length {
            let (balance, owner) = bytes.split_at(8);
            (balance, owner)
        } else {
            return Err(PhotonApiError::ValidationError(format!(
                "Invalid cursor length. Expected {}. Received {}.",
                expected_cursor_length,
                bytes.len()
            )));
        };
        let balance = LittleEndian::read_u64(balance);

        filter = filter.and(
            token_owner_balances::Column::Amount.lt(balance).or(
                token_owner_balances::Column::Amount
                    .eq(balance)
                    .and(token_owner_balances::Column::Owner.lt::<Vec<u8>>(owner.into())),
            ),
        );
    }
    let limit = limit.map(|l| l.value()).unwrap_or(PAGE_LIMIT);

    let items = if is_sqlite(conn) {
        token_owner_balances::Entity::find()
            .select_only()
            .column(token_owner_balances::Column::Owner)
            .column(token_owner_balances::Column::Amount)
            .filter(filter)
            .order_by_desc(token_owner_balances::Column::Amount)
            .order_by_desc(token_owner_balances::Column::Owner)
            .limit(limit)
            .into_model::<OwnerBalanceModelString>()
            .all(conn)
            .await?
            .drain(..)
            .map(|m| {
                Ok(OwnerBalance {
                    owner: m.owner.try_into()?,
                    balance: UnsignedInteger(parse_balance_string(&m.amount)?),
                })
            })
            .collect::<Result<Vec<OwnerBalance>, PhotonApiError>>()?
    } else {
        token_owner_balances::Entity::find()
            .select_only()
            .column(token_owner_balances::Column::Owner)
            .column(token_owner_balances::Column::Amount)
            .filter(filter)
            .order_by_desc(token_owner_balances::Column::Amount)
            .order_by_desc(token_owner_balances::Column::Owner)
            .limit(limit)
            .into_model::<OwnerBalanceModel>()
            .all(conn)
            .await?
            .drain(..)
            .map(|m| {
                Ok(OwnerBalance {
                    owner: m.owner.try_into()?,
                    balance: UnsignedInteger(parse_decimal(m.amount)?),
                })
            })
            .collect::<Result<Vec<OwnerBalance>, PhotonApiError>>()?
    };

    let mut cursor = items.last().map(|item| {
        Base58String({
            let item = item.clone();
            let mut bytes: Vec<u8> = Vec::new();
            bytes.extend_from_slice(&item.balance.0.to_le_bytes());
            bytes.extend_from_slice(&item.owner.0.to_bytes());
            bytes
        })
    });
    if items.len() < limit as usize {
        cursor = None;
    }

    Ok(OwnerBalancesResponse {
        value: OwnerBalanceList { items, cursor },
        context,
    })
}
