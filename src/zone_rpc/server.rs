//! JSON-RPC server for the local/dev Zone RPC sidecar.

use std::net::SocketAddr;

use hyper::Method;
use jsonrpsee::{
    core::Error as RpcError,
    server::{ServerBuilder, ServerHandle},
    types::error::CallError,
    RpcModule,
};
use tower_http::cors::{Any, CorsLayer};

use crate::zone_rpc::api::{
    FetchDecryptedUtxosRequest, FetchProofInputsRequest, FetchProofsRequest, FetchUtxosRequest,
    GetProofJobRequest, GetRelayerJobRequest, GetZoneInfoRequest, SubmitIntentRequest, ZoneRpcApi,
    ZoneRpcApiError,
};

pub const ZONE_RPC_METHODS: [&str; 8] = [
    "fetch_utxos",
    "fetch_decrypted_utxos",
    "fetch_proof_inputs",
    "fetch_proofs",
    "submit_intent",
    "get_proof_job",
    "get_relayer_job",
    "get_zone_info",
];

pub async fn run_zone_rpc_server(
    api: ZoneRpcApi,
    port: u16,
    max_connections: u32,
) -> Result<ServerHandle, anyhow::Error> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let cors = CorsLayer::new()
        .allow_methods([Method::POST])
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new().layer(cors);
    let server = ServerBuilder::default()
        .max_connections(max_connections)
        .set_middleware(middleware)
        .build(addr)
        .await?;
    let rpc_module = build_zone_rpc_module(api)?;
    server.start(rpc_module).map_err(|err| anyhow::anyhow!(err))
}

pub(crate) fn build_zone_rpc_module(
    api: ZoneRpcApi,
) -> Result<RpcModule<ZoneRpcApi>, anyhow::Error> {
    let mut module = RpcModule::new(api);

    module.register_async_method("fetch_utxos", |rpc_params, rpc_context| async move {
        let api = rpc_context.as_ref();
        let payload = rpc_params.parse::<FetchUtxosRequest>()?;
        api.fetch_utxos(payload).await.map_err(zone_rpc_error)
    })?;

    module.register_async_method(
        "fetch_decrypted_utxos",
        |rpc_params, rpc_context| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse::<FetchDecryptedUtxosRequest>()?;
            api.fetch_decrypted_utxos(payload)
                .await
                .map_err(zone_rpc_error)
        },
    )?;

    module.register_async_method("fetch_proof_inputs", |rpc_params, rpc_context| async move {
        let api = rpc_context.as_ref();
        let payload = rpc_params.parse::<FetchProofInputsRequest>()?;
        api.fetch_proof_inputs(payload)
            .await
            .map_err(zone_rpc_error)
    })?;

    module.register_async_method("fetch_proofs", |rpc_params, rpc_context| async move {
        let api = rpc_context.as_ref();
        let payload = rpc_params.parse::<FetchProofsRequest>()?;
        api.fetch_proofs(payload).await.map_err(zone_rpc_error)
    })?;

    module.register_async_method("submit_intent", |rpc_params, rpc_context| async move {
        let api = rpc_context.as_ref();
        let payload = rpc_params.parse::<SubmitIntentRequest>()?;
        api.submit_intent(payload).await.map_err(zone_rpc_error)
    })?;

    module.register_async_method("get_proof_job", |rpc_params, rpc_context| async move {
        let api = rpc_context.as_ref();
        let payload = rpc_params.parse::<GetProofJobRequest>()?;
        api.get_proof_job(payload).await.map_err(zone_rpc_error)
    })?;

    module.register_async_method("get_relayer_job", |rpc_params, rpc_context| async move {
        let api = rpc_context.as_ref();
        let payload = rpc_params.parse::<GetRelayerJobRequest>()?;
        api.get_relayer_job(payload).await.map_err(zone_rpc_error)
    })?;

    module.register_async_method("get_zone_info", |rpc_params, rpc_context| async move {
        let api = rpc_context.as_ref();
        let payload = rpc_params.parse::<GetZoneInfoRequest>()?;
        api.get_zone_info(payload).await.map_err(zone_rpc_error)
    })?;

    Ok(module)
}

fn zone_rpc_error(error: ZoneRpcApiError) -> RpcError {
    RpcError::Call(CallError::from_std_error(error))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sea_orm::Database;

    use super::*;
    use crate::zone_rpc::private_api::ZoneRpcPrivateApi;
    use crate::zone_rpc::private_db::SqlZonePrivateStore;

    #[tokio::test]
    async fn rpc_module_exposes_only_design_methods() {
        let photon_conn = Database::connect("sqlite::memory:")
            .await
            .expect("photon sqlite db should open");
        let private_conn = Database::connect("sqlite::memory:")
            .await
            .expect("private sqlite db should open");
        let private_api = ZoneRpcPrivateApi::new_unchecked_for_local_testing(
            SqlZonePrivateStore::new(private_conn),
        );
        let api = ZoneRpcApi::new(std::sync::Arc::new(photon_conn), private_api);
        let module = build_zone_rpc_module(api).expect("rpc module should build");

        let actual = module.method_names().collect::<BTreeSet<_>>();
        let expected = ZONE_RPC_METHODS.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }
}
