use crate::common::typedefs::unsigned_integer::UnsignedInteger;
use crate::dao::generated::token_accounts;
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use serde::{Deserialize, Serialize};

use super::super::error::PhotonApiError;
use super::utils::{
    is_sqlite, parse_balance_string, parse_decimal, AccountDataTable, BalanceModel,
    BalanceModelString, CompressedAccountRequest,
};
use crate::common::typedefs::context::Context;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
// This is a struct because in the future we might add other fields here like decimals or uiAmount,
// which is a string representation with decimals in the form of "10.00"
pub struct TokenAccountBalance {
    pub amount: UnsignedInteger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
// We do not use generics to simplify documentation generation.
pub struct GetCompressedTokenAccountBalanceResponse {
    pub context: Context,
    pub value: TokenAccountBalance,
}

pub async fn get_compressed_token_account_balance(
    conn: &DatabaseConnection,
    request: CompressedAccountRequest,
) -> Result<GetCompressedTokenAccountBalanceResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let id = request.parse_id()?;

    let balance = if is_sqlite(conn) {
        token_accounts::Entity::find()
            .select_only()
            .column(token_accounts::Column::Amount)
            .filter(id.filter(AccountDataTable::TokenAccounts))
            .into_model::<BalanceModelString>()
            .one(conn)
            .await?
            .map(|x| parse_balance_string(&x.amount))
            .transpose()?
            .unwrap_or(0)
    } else {
        token_accounts::Entity::find()
            .select_only()
            .column(token_accounts::Column::Amount)
            .filter(id.filter(AccountDataTable::TokenAccounts))
            .into_model::<BalanceModel>()
            .one(conn)
            .await?
            .map(|x| parse_decimal(x.amount))
            .transpose()?
            .unwrap_or(0)
    };

    Ok(GetCompressedTokenAccountBalanceResponse {
        value: TokenAccountBalance {
            amount: UnsignedInteger(balance),
        },
        context,
    })
}
