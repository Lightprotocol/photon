use sea_orm::DatabaseConnection;
use solana_account::Account as SolanaAccount;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_program_option::COption;
use solana_program_pack::Pack;
use solana_pubkey::{pubkey, Pubkey};
use spl_token_interface::state::{Account as SplTokenAccount, AccountState as SplAccountState};

use crate::api::error::PhotonApiError;
use crate::api::method::get_compressed_token_accounts_by_owner::get_compressed_token_accounts_by_owner_v2;
use crate::api::method::utils::GetCompressedTokenAccountsByOwner;
use crate::common::typedefs::account::AccountV2;
use crate::common::typedefs::bs64_string::Base64String;
use crate::common::typedefs::context::Context;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::token_data::{AccountState, TokenData};
use crate::common::typedefs::unsigned_integer::UnsignedInteger;
use crate::ingester::persist::LIGHT_TOKEN_PROGRAM_ID;

use super::racing::hot_lookup;
use super::types::{
    AtaInterfaceValue, GetAtaDerivedAddresses, GetAtaHotEntry, GetAtaHotSources,
    GetAtaInterfaceRequest, GetAtaInterfaceResponse, GetAtaProgramMode, SolanaAccountData,
};
#[cfg(test)]
use super::types::GetAtaInterfaceConfig;

const SPL_TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const COMPRESSED_ONLY_DISCRIMINATOR: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    LightHot,
    LightCold,
    SplHot,
    SplCold,
    Token2022Hot,
    Token2022Cold,
}

impl SourceKind {
    fn rank(self) -> u8 {
        match self {
            SourceKind::LightHot => 0,
            SourceKind::LightCold => 1,
            SourceKind::SplHot => 2,
            SourceKind::Token2022Hot => 3,
            SourceKind::SplCold => 4,
            SourceKind::Token2022Cold => 5,
        }
    }

    fn is_hot(self) -> bool {
        matches!(
            self,
            SourceKind::LightHot | SourceKind::SplHot | SourceKind::Token2022Hot
        )
    }
}

#[derive(Debug, Clone)]
struct Source {
    kind: SourceKind,
    amount: u64,
    delegate: Option<Pubkey>,
    delegated_amount: u64,
    frozen: bool,
    slot_created: u64,
    lamports: u64,
    owner: SerializablePubkey,
    executable: bool,
    rent_epoch: u64,
    spl: SplTokenAccount,
}

#[derive(Debug, Clone, Copy)]
struct RequestOptions {
    commitment: super::types::RpcCommitment,
    mode: GetAtaProgramMode,
    wrap: bool,
    allow_owner_off_curve: bool,
    min_context_slot: Option<u64>,
}

fn derive_ata(
    owner: &SerializablePubkey,
    mint: &SerializablePubkey,
    token_program_id: &Pubkey,
    associated_program_id: &Pubkey,
) -> SerializablePubkey {
    let seeds = &[owner.0.as_ref(), token_program_id.as_ref(), mint.0.as_ref()];
    let (ata, _) = Pubkey::find_program_address(seeds, associated_program_id);
    SerializablePubkey::from(ata)
}

fn extension_data_size(discriminator: u8) -> Option<usize> {
    match discriminator {
        0..=18 => Some(0),
        19 => None,
        20..=28 => Some(0),
        29 => Some(8),
        30 => Some(1),
        31 => Some(17),
        32 => None,
        _ => None,
    }
}

fn extract_delegated_amount_from_tlv(tlv: Option<&Base64String>) -> Option<u64> {
    let bytes = tlv?.0.as_slice();
    if bytes.len() < 4 {
        return None;
    }

    let mut offset = 0usize;
    let vec_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;

    for _ in 0..vec_len {
        if offset >= bytes.len() {
            return None;
        }

        let discriminator = bytes[offset];
        offset += 1;

        if discriminator == COMPRESSED_ONLY_DISCRIMINATOR {
            if offset + 8 > bytes.len() {
                return None;
            }
            let amount = u64::from_le_bytes(bytes[offset..offset + 8].try_into().ok()?);
            return Some(amount);
        }

        let size = extension_data_size(discriminator)?;
        if offset + size > bytes.len() {
            return None;
        }
        offset += size;
    }

    None
}

fn delegated_contribution(source: &Source) -> u64 {
    if source.delegate.is_none() {
        return 0;
    }
    source.delegated_amount.min(source.amount)
}

fn token_data_to_spl_account(token_data: &TokenData) -> SplTokenAccount {
    let delegated_amount = if token_data.delegate.is_some() {
        extract_delegated_amount_from_tlv(token_data.tlv.as_ref())
            .unwrap_or(token_data.amount.0)
            .min(token_data.amount.0)
    } else {
        0
    };

    SplTokenAccount {
        mint: Pubkey::from(token_data.mint.0.to_bytes()),
        owner: Pubkey::from(token_data.owner.0.to_bytes()),
        amount: token_data.amount.0,
        delegate: match token_data.delegate {
            Some(d) => COption::Some(Pubkey::from(d.0.to_bytes())),
            None => COption::None,
        },
        state: match token_data.state {
            AccountState::initialized => SplAccountState::Initialized,
            AccountState::frozen => SplAccountState::Frozen,
        },
        is_native: COption::None,
        delegated_amount,
        close_authority: COption::None,
    }
}

fn source_kind_for_mode(mode: GetAtaProgramMode) -> SourceKind {
    match mode {
        GetAtaProgramMode::Auto | GetAtaProgramMode::Light => SourceKind::LightCold,
        GetAtaProgramMode::Spl => SourceKind::SplCold,
        GetAtaProgramMode::Token2022 => SourceKind::Token2022Cold,
    }
}

fn build_synthetic_account_from_sources(sources: &mut [Source]) -> Option<SolanaAccountData> {
    if sources.is_empty() {
        return None;
    }

    sources.sort_by(|a, b| {
        a.kind
            .rank()
            .cmp(&b.kind.rank())
            .then_with(|| b.slot_created.cmp(&a.slot_created))
    });

    let total_amount_u128: u128 = sources.iter().map(|s| s.amount as u128).sum();
    let total_amount = u64::try_from(total_amount_u128)
        .map_err(|_| ())
        .ok()
        .unwrap_or(u64::MAX);

    let canonical_delegate = sources
        .iter()
        .find(|s| s.kind.is_hot() && s.delegate.is_some())
        .and_then(|s| s.delegate)
        .or_else(|| {
            sources
                .iter()
                .find(|s| !s.kind.is_hot() && s.delegate.is_some())
                .and_then(|s| s.delegate)
        });

    let canonical_delegated_u128: u128 = canonical_delegate
        .map(|delegate| {
            sources
                .iter()
                .filter(|s| s.delegate == Some(delegate))
                .map(delegated_contribution)
                .map(u128::from)
                .sum()
        })
        .unwrap_or(0);

    let canonical_delegated = u64::try_from(canonical_delegated_u128)
        .map_err(|_| ())
        .ok()
        .unwrap_or(u64::MAX)
        .min(total_amount);

    let any_frozen = sources.iter().any(|s| s.frozen);

    let primary = &sources[0];
    let mut spl = primary.spl;
    spl.amount = total_amount;
    spl.delegate = canonical_delegate
        .map(COption::Some)
        .unwrap_or(COption::None);
    spl.delegated_amount = canonical_delegated;
    spl.state = if any_frozen {
        SplAccountState::Frozen
    } else {
        SplAccountState::Initialized
    };

    let mut spl_bytes = vec![0u8; SplTokenAccount::LEN];
    SplTokenAccount::pack(spl, &mut spl_bytes).expect("buffer is exactly LEN bytes");

    Some(SolanaAccountData {
        lamports: UnsignedInteger(primary.lamports),
        data: Base64String(spl_bytes),
        owner: primary.owner,
        executable: primary.executable,
        rent_epoch: UnsignedInteger(primary.rent_epoch),
        space: UnsignedInteger(SplTokenAccount::LEN as u64),
    })
}

fn hot_entry_from_account(
    address: SerializablePubkey,
    account: &SolanaAccount,
    expected_program: Pubkey,
    mint: SerializablePubkey,
    kind: SourceKind,
) -> Option<(GetAtaHotEntry, Source)> {
    if account.owner != expected_program {
        return None;
    }

    let spl = SplTokenAccount::unpack(&account.data).ok()?;
    if spl.mint.to_bytes() != mint.0.to_bytes() {
        return None;
    }

    let delegate = match spl.delegate {
        COption::Some(d) => Some(d),
        COption::None => None,
    };
    let entry = GetAtaHotEntry {
        address,
        amount: UnsignedInteger(spl.amount),
    };
    let source = Source {
        kind,
        amount: spl.amount,
        delegate,
        delegated_amount: spl.delegated_amount,
        frozen: spl.state == SplAccountState::Frozen,
        slot_created: u64::MAX,
        lamports: account.lamports,
        owner: SerializablePubkey::from(account.owner.to_bytes()),
        executable: account.executable,
        rent_epoch: account.rent_epoch,
        spl,
    };
    Some((entry, source))
}

fn canonical_key_for_mode(
    mode: GetAtaProgramMode,
    light_ata: SerializablePubkey,
    spl_ata: SerializablePubkey,
    token2022_ata: SerializablePubkey,
) -> SerializablePubkey {
    match mode {
        GetAtaProgramMode::Auto | GetAtaProgramMode::Light => light_ata,
        GetAtaProgramMode::Spl => spl_ata,
        GetAtaProgramMode::Token2022 => token2022_ata,
    }
}

fn mode_from_program_id(program_id: Option<SerializablePubkey>) -> Result<Option<GetAtaProgramMode>, PhotonApiError> {
    let Some(program_id) = program_id else {
        return Ok(None);
    };
    let key = Pubkey::from(program_id.0.to_bytes());
    if key == LIGHT_TOKEN_PROGRAM_ID {
        Ok(Some(GetAtaProgramMode::Light))
    } else if key == SPL_TOKEN_PROGRAM_ID {
        Ok(Some(GetAtaProgramMode::Spl))
    } else if key == TOKEN_2022_PROGRAM_ID {
        Ok(Some(GetAtaProgramMode::Token2022))
    } else {
        Err(PhotonApiError::ValidationError(format!(
            "Unsupported programId {}. Expected light token, SPL token, or Token-2022 program id",
            key
        )))
    }
}

fn resolve_request_options(request: &GetAtaInterfaceRequest) -> Result<RequestOptions, PhotonApiError> {
    let cfg = request.config.as_ref();
    let commitment = cfg
        .and_then(|c| c.commitment)
        .unwrap_or_default();
    let mode = mode_from_program_id(cfg.and_then(|c| c.program_id))?
        .unwrap_or_default();
    let wrap = cfg.and_then(|c| c.wrap).unwrap_or(false);
    let allow_owner_off_curve = cfg
        .and_then(|c| c.allow_owner_off_curve)
        .unwrap_or(false);
    let min_context_slot = cfg.and_then(|c| c.min_context_slot).map(|v| v.0);

    if wrap && mode != GetAtaProgramMode::Auto {
        return Err(PhotonApiError::ValidationError(
            "wrap=true is only valid when config.programId is not set (auto mode)".to_string(),
        ));
    }

    Ok(RequestOptions {
        commitment,
        mode,
        wrap,
        allow_owner_off_curve,
        min_context_slot,
    })
}

/// Return canonical ATA interface for (owner, mint) with hot/cold aggregation.
pub async fn get_ata_interface(
    conn: &DatabaseConnection,
    rpc_client: &RpcClient,
    request: GetAtaInterfaceRequest,
) -> Result<GetAtaInterfaceResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let options = resolve_request_options(&request)?;

    if let Some(min_context_slot) = options.min_context_slot {
        if context.slot < min_context_slot {
            return Err(PhotonApiError::StaleSlot(min_context_slot - context.slot));
        }
    }

    if !options.allow_owner_off_curve && !request.owner.0.is_on_curve() {
        return Err(PhotonApiError::ValidationError(
            "Owner is off-curve; set allowOwnerOffCurve=true to allow PDA owners".to_string(),
        ));
    }

    let light_ata = derive_ata(
        &request.owner,
        &request.mint,
        &LIGHT_TOKEN_PROGRAM_ID,
        &LIGHT_TOKEN_PROGRAM_ID,
    );
    let spl_ata = derive_ata(
        &request.owner,
        &request.mint,
        &SPL_TOKEN_PROGRAM_ID,
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    );
    let token2022_ata = derive_ata(
        &request.owner,
        &request.mint,
        &TOKEN_2022_PROGRAM_ID,
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    );
    let key = canonical_key_for_mode(options.mode, light_ata, spl_ata, token2022_ata);

    let fetch_light_hot = matches!(options.mode, GetAtaProgramMode::Auto | GetAtaProgramMode::Light);
    let fetch_spl_hot = matches!(options.mode, GetAtaProgramMode::Spl)
        || (options.mode == GetAtaProgramMode::Auto && options.wrap);
    let fetch_t22_hot = matches!(options.mode, GetAtaProgramMode::Token2022)
        || (options.mode == GetAtaProgramMode::Auto && options.wrap);

    let mut hot_sources = GetAtaHotSources {
        light: None,
        spl: None,
        token2022: None,
    };
    let mut sources: Vec<Source> = Vec::new();

    if fetch_light_hot {
        if let Ok(hot) = hot_lookup(
            rpc_client,
            &Pubkey::from(light_ata.0.to_bytes()),
            options.commitment,
        )
        .await
        {
            if let Some(account) = hot.account.as_ref() {
                if let Some((entry, src)) = hot_entry_from_account(
                    light_ata,
                    account,
                    LIGHT_TOKEN_PROGRAM_ID,
                    request.mint,
                    SourceKind::LightHot,
                ) {
                    hot_sources.light = Some(entry);
                    sources.push(src);
                }
            }
        }
    }

    if fetch_spl_hot {
        if let Ok(hot) = hot_lookup(
            rpc_client,
            &Pubkey::from(spl_ata.0.to_bytes()),
            options.commitment,
        )
        .await
        {
            if let Some(account) = hot.account.as_ref() {
                if let Some((entry, src)) = hot_entry_from_account(
                    spl_ata,
                    account,
                    SPL_TOKEN_PROGRAM_ID,
                    request.mint,
                    SourceKind::SplHot,
                ) {
                    hot_sources.spl = Some(entry);
                    sources.push(src);
                }
            }
        }
    }

    if fetch_t22_hot {
        if let Ok(hot) = hot_lookup(
            rpc_client,
            &Pubkey::from(token2022_ata.0.to_bytes()),
            options.commitment,
        )
        .await
        {
            if let Some(account) = hot.account.as_ref() {
                if let Some((entry, src)) = hot_entry_from_account(
                    token2022_ata,
                    account,
                    TOKEN_2022_PROGRAM_ID,
                    request.mint,
                    SourceKind::Token2022Hot,
                ) {
                    hot_sources.token2022 = Some(entry);
                    sources.push(src);
                }
            }
        }
    }

    let cold_response = get_compressed_token_accounts_by_owner_v2(
        conn,
        GetCompressedTokenAccountsByOwner {
            owner: request.owner,
            mint: Some(request.mint),
            cursor: None,
            limit: None,
        },
    )
    .await?;

    let mut cold_accounts: Vec<AccountV2> = Vec::new();
    let mut cold_sources: Vec<Source> = cold_response
        .value
        .items
        .into_iter()
        .map(|item| {
            cold_accounts.push(item.account.clone());
            let spl = token_data_to_spl_account(&item.token_data);
            Source {
                kind: source_kind_for_mode(options.mode),
                amount: item.token_data.amount.0,
                delegate: item
                    .token_data
                    .delegate
                    .map(|d| Pubkey::from(d.0.to_bytes())),
                delegated_amount: spl.delegated_amount,
                frozen: item.token_data.state == AccountState::frozen,
                slot_created: item.account.slot_created.0,
                lamports: item.account.lamports.0,
                owner: item.account.owner,
                executable: false,
                rent_epoch: 0,
                spl,
            }
        })
        .collect();

    cold_sources.sort_by(|a, b| b.slot_created.cmp(&a.slot_created));
    sources.extend(cold_sources);

    let account = build_synthetic_account_from_sources(&mut sources);
    let cold = (!cold_accounts.is_empty()).then_some(cold_accounts);

    let value = account.map(|account| AtaInterfaceValue {
        key,
        owner: request.owner,
        mint: request.mint,
        mode: options.mode,
        wrap: options.wrap,
        addresses: GetAtaDerivedAddresses {
            light: light_ata,
            spl: spl_ata,
            token2022: token2022_ata,
            canonical: key,
        },
        account,
        cold,
        hot: hot_sources,
    });

    Ok(GetAtaInterfaceResponse { context, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hot_source(
        kind: SourceKind,
        amount: u64,
        delegate: Option<Pubkey>,
        delegated_amount: u64,
    ) -> Source {
        Source {
            kind,
            amount,
            delegate,
            delegated_amount,
            frozen: false,
            slot_created: u64::MAX,
            lamports: 1,
            owner: SerializablePubkey::default(),
            executable: false,
            rent_epoch: 0,
            spl: SplTokenAccount {
                mint: Pubkey::new_unique(),
                owner: Pubkey::new_unique(),
                amount,
                delegate: delegate.map(COption::Some).unwrap_or(COption::None),
                state: SplAccountState::Initialized,
                is_native: COption::None,
                delegated_amount,
                close_authority: COption::None,
            },
        }
    }

    #[test]
    fn canonical_delegate_prefers_first_hot_source() {
        let d1 = Pubkey::new_unique();
        let d2 = Pubkey::new_unique();
        let mut sources = vec![
            hot_source(SourceKind::SplHot, 10, Some(d2), 9),
            hot_source(SourceKind::LightHot, 10, Some(d1), 8),
        ];

        let data = build_synthetic_account_from_sources(&mut sources).expect("expected account");
        let parsed = SplTokenAccount::unpack(&data.data.0).expect("valid spl");
        assert_eq!(parsed.delegate, COption::Some(d1));
        assert_eq!(parsed.delegated_amount, 8);
    }

    #[test]
    fn different_hot_delegate_does_not_contribute() {
        let d1 = Pubkey::new_unique();
        let d2 = Pubkey::new_unique();
        let mut sources = vec![
            hot_source(SourceKind::LightHot, 100, Some(d1), 40),
            hot_source(SourceKind::SplHot, 50, Some(d2), 50),
        ];

        let data = build_synthetic_account_from_sources(&mut sources).expect("expected account");
        let parsed = SplTokenAccount::unpack(&data.data.0).expect("valid spl");
        assert_eq!(parsed.delegate, COption::Some(d1));
        assert_eq!(parsed.amount, 150);
        assert_eq!(parsed.delegated_amount, 40);
    }

    #[test]
    fn wrap_requires_auto_mode() {
        let req = GetAtaInterfaceRequest {
            owner: SerializablePubkey::default(),
            mint: SerializablePubkey::default(),
            config: Some(GetAtaInterfaceConfig {
                wrap: Some(true),
                program_id: Some(SerializablePubkey::from(SPL_TOKEN_PROGRAM_ID.to_bytes())),
                ..Default::default()
            }),
        };
        let err = resolve_request_options(&req).expect_err("expected validation error");
        assert_eq!(
            err,
            PhotonApiError::ValidationError(
                "wrap=true is only valid when config.programId is not set (auto mode)".to_string()
            )
        );
    }

    #[test]
    fn unsupported_program_id_is_rejected() {
        let req = GetAtaInterfaceRequest {
            owner: SerializablePubkey::default(),
            mint: SerializablePubkey::default(),
            config: Some(GetAtaInterfaceConfig {
                program_id: Some(SerializablePubkey::new_unique()),
                ..Default::default()
            }),
        };
        let err = resolve_request_options(&req).expect_err("expected validation error");
        assert!(matches!(err, PhotonApiError::ValidationError(_)));
    }

    #[test]
    fn program_id_maps_to_mode() {
        let req = GetAtaInterfaceRequest {
            owner: SerializablePubkey::default(),
            mint: SerializablePubkey::default(),
            config: Some(GetAtaInterfaceConfig {
                program_id: Some(SerializablePubkey::from(TOKEN_2022_PROGRAM_ID.to_bytes())),
                ..Default::default()
            }),
        };
        let options = resolve_request_options(&req).expect("expected options");
        assert_eq!(options.mode, GetAtaProgramMode::Token2022);
    }
}
