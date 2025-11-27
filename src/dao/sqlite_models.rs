// SQLite-specific models that use String for large integer fields
// These are needed because SQLite TEXT columns can't be decoded as Decimal

use sea_orm::FromQueryResult;
use sqlx::types::Decimal;
use std::str::FromStr;

use super::generated::{accounts, token_accounts};

/// SQLite model for accounts table - uses String for lamports and discriminator
#[derive(Clone, Debug, FromQueryResult)]
pub struct AccountModelSqlite {
    pub hash: Vec<u8>,
    pub data: Option<Vec<u8>>,
    pub data_hash: Option<Vec<u8>>,
    pub address: Option<Vec<u8>>,
    pub owner: Vec<u8>,
    pub tree: Vec<u8>,
    pub leaf_index: i64,
    pub seq: Option<i64>,
    pub slot_created: i64,
    pub spent: bool,
    pub prev_spent: Option<bool>,
    pub lamports: String,
    pub discriminator: Option<String>,
    pub tree_type: Option<i32>,
    pub nullified_in_tree: bool,
    pub nullifier_queue_index: Option<i64>,
    pub in_output_queue: bool,
    pub queue: Option<Vec<u8>>,
    pub nullifier: Option<Vec<u8>>,
    pub tx_hash: Option<Vec<u8>>,
}

/// SQLite model for token_accounts table - uses String for amount
#[derive(Clone, Debug, FromQueryResult)]
pub struct TokenAccountModelSqlite {
    pub hash: Vec<u8>,
    pub owner: Vec<u8>,
    pub mint: Vec<u8>,
    pub delegate: Option<Vec<u8>>,
    pub state: i32,
    pub spent: bool,
    pub prev_spent: Option<bool>,
    pub amount: String,
    pub tlv: Option<Vec<u8>>,
}

/// Joint query result for token accounts with their base accounts (SQLite)
#[derive(Clone, Debug, FromQueryResult)]
pub struct TokenAccountWithAccountSqlite {
    // Token account fields
    pub hash: Vec<u8>,
    pub ta_owner: Vec<u8>,
    pub mint: Vec<u8>,
    pub delegate: Option<Vec<u8>>,
    pub state: i32,
    pub ta_spent: bool,
    pub ta_prev_spent: Option<bool>,
    pub amount: String,
    pub tlv: Option<Vec<u8>>,
    // Account fields (prefixed to avoid collision)
    pub a_hash: Vec<u8>,
    pub data: Option<Vec<u8>>,
    pub data_hash: Option<Vec<u8>>,
    pub address: Option<Vec<u8>>,
    pub a_owner: Vec<u8>,
    pub tree: Vec<u8>,
    pub leaf_index: i64,
    pub seq: Option<i64>,
    pub slot_created: i64,
    pub a_spent: bool,
    pub a_prev_spent: Option<bool>,
    pub lamports: String,
    pub discriminator: Option<String>,
    pub tree_type: Option<i32>,
    pub nullified_in_tree: bool,
    pub nullifier_queue_index: Option<i64>,
    pub in_output_queue: bool,
    pub queue: Option<Vec<u8>>,
    pub nullifier: Option<Vec<u8>>,
    pub tx_hash: Option<Vec<u8>>,
}

fn parse_decimal_string(s: &str) -> Decimal {
    // Handle potential decimal point (shouldn't have one, but defensive)
    let s = s.split('.').next().unwrap_or(s);
    Decimal::from_str(s).unwrap_or_else(|_| Decimal::from(0))
}

fn parse_optional_decimal_string(s: Option<&String>) -> Option<Decimal> {
    s.map(|s| parse_decimal_string(s))
}

impl From<AccountModelSqlite> for accounts::Model {
    fn from(sqlite: AccountModelSqlite) -> Self {
        accounts::Model {
            hash: sqlite.hash,
            data: sqlite.data,
            data_hash: sqlite.data_hash,
            address: sqlite.address,
            owner: sqlite.owner,
            tree: sqlite.tree,
            leaf_index: sqlite.leaf_index,
            seq: sqlite.seq,
            slot_created: sqlite.slot_created,
            spent: sqlite.spent,
            prev_spent: sqlite.prev_spent,
            lamports: parse_decimal_string(&sqlite.lamports),
            discriminator: parse_optional_decimal_string(sqlite.discriminator.as_ref()),
            tree_type: sqlite.tree_type,
            nullified_in_tree: sqlite.nullified_in_tree,
            nullifier_queue_index: sqlite.nullifier_queue_index,
            in_output_queue: sqlite.in_output_queue,
            queue: sqlite.queue,
            nullifier: sqlite.nullifier,
            tx_hash: sqlite.tx_hash,
        }
    }
}

impl From<TokenAccountModelSqlite> for token_accounts::Model {
    fn from(sqlite: TokenAccountModelSqlite) -> Self {
        token_accounts::Model {
            hash: sqlite.hash,
            owner: sqlite.owner,
            mint: sqlite.mint,
            delegate: sqlite.delegate,
            state: sqlite.state,
            spent: sqlite.spent,
            prev_spent: sqlite.prev_spent,
            amount: parse_decimal_string(&sqlite.amount),
            tlv: sqlite.tlv,
        }
    }
}

impl TokenAccountWithAccountSqlite {
    pub fn into_tuple(self) -> (token_accounts::Model, Option<accounts::Model>) {
        let token_account = token_accounts::Model {
            hash: self.hash,
            owner: self.ta_owner,
            mint: self.mint,
            delegate: self.delegate,
            state: self.state,
            spent: self.ta_spent,
            prev_spent: self.ta_prev_spent,
            amount: parse_decimal_string(&self.amount),
            tlv: self.tlv,
        };

        let account = accounts::Model {
            hash: self.a_hash,
            data: self.data,
            data_hash: self.data_hash,
            address: self.address,
            owner: self.a_owner,
            tree: self.tree,
            leaf_index: self.leaf_index,
            seq: self.seq,
            slot_created: self.slot_created,
            spent: self.a_spent,
            prev_spent: self.a_prev_spent,
            lamports: parse_decimal_string(&self.lamports),
            discriminator: parse_optional_decimal_string(self.discriminator.as_ref()),
            tree_type: self.tree_type,
            nullified_in_tree: self.nullified_in_tree,
            nullifier_queue_index: self.nullifier_queue_index,
            in_output_queue: self.in_output_queue,
            queue: self.queue,
            nullifier: self.nullifier,
            tx_hash: self.tx_hash,
        };

        (token_account, Some(account))
    }
}

/// Raw SQL for selecting all account columns
pub const ACCOUNT_COLUMNS_SQL: &str = r#"
    hash, data, data_hash, address, owner, tree, leaf_index, seq, slot_created,
    spent, prev_spent, lamports, discriminator, tree_type, nullified_in_tree,
    nullifier_queue_index, in_output_queue, queue, nullifier, tx_hash
"#;

/// Raw SQL for selecting all token_account columns joined with accounts
pub const TOKEN_ACCOUNT_WITH_ACCOUNT_SQL: &str = r#"
    token_accounts.hash as hash,
    token_accounts.owner as ta_owner,
    token_accounts.mint as mint,
    token_accounts.delegate as delegate,
    token_accounts.state as state,
    token_accounts.spent as ta_spent,
    token_accounts.prev_spent as ta_prev_spent,
    token_accounts.amount as amount,
    token_accounts.tlv as tlv,
    accounts.hash as a_hash,
    accounts.data as data,
    accounts.data_hash as data_hash,
    accounts.address as address,
    accounts.owner as a_owner,
    accounts.tree as tree,
    accounts.leaf_index as leaf_index,
    accounts.seq as seq,
    accounts.slot_created as slot_created,
    accounts.spent as a_spent,
    accounts.prev_spent as a_prev_spent,
    accounts.lamports as lamports,
    accounts.discriminator as discriminator,
    accounts.tree_type as tree_type,
    accounts.nullified_in_tree as nullified_in_tree,
    accounts.nullifier_queue_index as nullifier_queue_index,
    accounts.in_output_queue as in_output_queue,
    accounts.queue as queue,
    accounts.nullifier as nullifier,
    accounts.tx_hash as tx_hash
"#;
