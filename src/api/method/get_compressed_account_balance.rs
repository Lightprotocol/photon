use super::super::error::PhotonApiError;
use super::utils::CompressedAccountRequest;
use super::utils::{
    is_sqlite, parse_balance_string, parse_decimal, AccountBalanceResponse, AccountDataTable,
    LamportModel, LamportModelString,
};
use crate::common::typedefs::context::Context;
use crate::common::typedefs::unsigned_integer::UnsignedInteger;
use crate::dao::generated::accounts;
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};

pub async fn get_compressed_account_balance(
    conn: &DatabaseConnection,
    request: CompressedAccountRequest,
) -> Result<AccountBalanceResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let id = request.parse_id()?;

    let balance = if is_sqlite(conn) {
        accounts::Entity::find()
            .select_only()
            .column(accounts::Column::Lamports)
            .filter(id.filter(AccountDataTable::Accounts))
            .into_model::<LamportModelString>()
            .one(conn)
            .await?
            .map(|x| parse_balance_string(&x.lamports))
            .transpose()?
            .unwrap_or(0)
    } else {
        accounts::Entity::find()
            .select_only()
            .column(accounts::Column::Lamports)
            .filter(id.filter(AccountDataTable::Accounts))
            .into_model::<LamportModel>()
            .one(conn)
            .await?
            .map(|x| parse_decimal(x.lamports))
            .transpose()?
            .unwrap_or(0)
    };

    Ok(AccountBalanceResponse {
        value: UnsignedInteger(balance),
        context,
    })
}
