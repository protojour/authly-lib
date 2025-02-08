use std::{sync::Arc, time::Duration};

use authly_common::proto::service::{self as proto};
use tonic::Streaming;

use crate::{
    access_control,
    connection::{make_connection, ConnectionParams},
    error, ClientState, Error,
};

pub struct WorkerSenders {
    pub reconfigured_tx: tokio::sync::watch::Sender<Arc<ConnectionParams>>,
    pub metadata_invalidated_tx: tokio::sync::watch::Sender<()>,
}

pub async fn spawn_background_worker(
    state: Arc<ClientState>,
    senders: WorkerSenders,
    closed_rx: tokio::sync::watch::Receiver<()>,
) -> Result<(), Error> {
    let msg_stream = init_message_stream(&state).await?;
    tokio::spawn(background_worker(state, senders, closed_rx, msg_stream));

    Ok(())
}

async fn background_worker(
    state: Arc<ClientState>,
    senders: WorkerSenders,
    mut closed_rx: tokio::sync::watch::Receiver<()>,
    mut msg_stream: Streaming<proto::ServiceMessage>,
) {
    loop {
        tokio::select! {
            msg_result = msg_stream.message() => {
                handle_message_result(&state, msg_result, &mut msg_stream, &senders).await;
            }
            _ = closed_rx.changed() => {
                tracing::info!("Authly channel closed");
                return;
            }
        }
    }
}

async fn handle_message_result(
    state: &ClientState,
    msg_result: Result<Option<proto::ServiceMessage>, tonic::Status>,
    msg_stream: &mut Streaming<proto::ServiceMessage>,
    senders: &WorkerSenders,
) {
    match msg_result {
        Ok(Some(msg)) => {
            if let Some(kind) = msg.service_message_kind {
                handle_message_kind(state, kind, msg_stream, senders).await;
            }
        }
        Ok(None) => {
            reconfigure_loop(state, msg_stream, senders).await;
        }
        Err(_error) => {
            reconfigure_loop(state, msg_stream, senders).await;
        }
    }
}

async fn handle_message_kind(
    state: &ClientState,
    msg_kind: proto::service_message::ServiceMessageKind,
    msg_stream: &mut Streaming<proto::ServiceMessage>,
    senders: &WorkerSenders,
) {
    tracing::info!(?msg_kind, "Received Authly message");

    match msg_kind {
        proto::service_message::ServiceMessageKind::ReloadCa(_) => {
            reconfigure_loop(state, msg_stream, senders).await;
        }
        proto::service_message::ServiceMessageKind::ReloadCache(_) => {
            reload_local_cache(state, senders).await;
        }
        proto::service_message::ServiceMessageKind::Ping(_) => {
            let _result = state
                .conn
                .load()
                .authly_service
                .clone()
                .pong(tonic::Request::new(proto::Empty {}))
                .await;
        }
    }
}

async fn reconfigure_loop(
    state: &ClientState,
    msg_stream: &mut Streaming<proto::ServiceMessage>,
    senders: &WorkerSenders,
) {
    loop {
        match try_reconfigure(state, msg_stream, senders).await {
            Ok(()) => return,
            Err(err) => {
                tracing::error!(?err, "background reconfigure error");

                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

async fn try_reconfigure(
    state: &ClientState,
    msg_stream: &mut Streaming<proto::ServiceMessage>,
    senders: &WorkerSenders,
) -> Result<(), Error> {
    let params = state.reconfigure.new_connection_params().await?;
    let connection = Arc::new(make_connection(params.clone()).await?);

    state.conn.store(connection.clone());

    *msg_stream = init_message_stream(state).await?;
    reload_local_cache(state, senders).await;

    if let Err(err) = senders.reconfigured_tx.send(params) {
        tracing::error!(?err, "Could not publish reconfigured connection params");
    }

    Ok(())
}

async fn init_message_stream(
    state: &ClientState,
) -> Result<Streaming<proto::ServiceMessage>, Error> {
    let mut current_service = state.conn.load().authly_service.clone();
    let response = current_service
        .messages(tonic::Request::new(proto::Empty {}))
        .await
        .map_err(error::tonic)?;

    Ok(response.into_inner())
}

async fn reload_local_cache(state: &ClientState, senders: &WorkerSenders) {
    match access_control::get_resource_property_mapping(state.conn.load().authly_service.clone())
        .await
    {
        Ok(property_mapping) => {
            state.resource_property_mapping.store(property_mapping);
            if let Err(err) = senders.metadata_invalidated_tx.send(()) {
                tracing::error!(?err, "Could not publish cache cleared");
            }
        }
        Err(err) => {
            tracing::error!(?err, "failed to reload resource property mapping");
        }
    }
}
