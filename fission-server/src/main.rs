//! fission-server

use anyhow::Result;

use axum::{extract::Extension, headers::HeaderName, routing::get, Router};
use axum_server::Handle;
use axum_tracing_opentelemetry::{opentelemetry_tracing_layer, response_with_trace_layer};
use fission_server::{
    app_state::AppState,
    db::{self, Pool},
    dns,
    docs::ApiDoc,
    metrics::{process, prom::setup_metrics_recorder},
    middleware::{self, request_ulid::MakeRequestUlid, runtime},
    models::email_verification::EmailVerificationCodeSender,
    router,
    routes::fallback::notfound_404,
    settings::{Otel, Settings},
    tracer::init_tracer,
    tracing_layers::{
        format_layer::LogFmtLayer,
        metrics_layer::{MetricsLayer, METRIC_META_PREFIX},
        storage_layer::StorageLayer,
    },
};
use http::header;
use metrics_exporter_prometheus::PrometheusHandle;
use reqwest_middleware::ClientBuilder;
use reqwest_retry::RetryTransientMiddleware;
use retry_policies::policies::ExponentialBackoffBuilder;
use std::{
    future::ready,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    process::exit,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    signal::{
        self,
        unix::{signal, SignalKind},
    },
};
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer, sensitive_headers::SetSensitiveHeadersLayer,
    timeout::TimeoutLayer, ServiceBuilderExt,
};
use tracing::{info, log};
use tracing_subscriber::{
    filter::{dynamic_filter_fn, filter_fn, LevelFilter},
    prelude::*,
    EnvFilter,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Request identifier field.
const REQUEST_ID: &str = "request_id";

#[tokio::main]
async fn main() -> Result<()> {
    let (stdout_writer, _stdout_guard) = tracing_appender::non_blocking(io::stdout());

    let settings = Settings::load()?;
    let db_pool = db::pool(
        &settings.database().url,
        settings.database().connect_timeout,
    )
    .await?;

    setup_tracing(stdout_writer, settings.otel())?;

    info!(
        subject = "app_settings",
        category = "init",
        "starting with settings: {:?}",
        settings,
    );

    let recorder_handle = setup_metrics_recorder()?;
    let cancellation_token = CancellationToken::new();

    let metrics_server = tokio::spawn(serve_metrics(
        recorder_handle,
        settings.clone(),
        cancellation_token.clone(),
    ));

    let app_server = tokio::spawn(serve_app(
        settings.clone(),
        db_pool.clone(),
        cancellation_token.clone(),
    ));
    let dns_server = tokio::spawn(serve_dns(settings, db_pool, cancellation_token.clone()));

    tokio::spawn(async move {
        capture_sigterm().await;

        cancellation_token.cancel();
        println!("\nCtrl+C received, shutting down. Press Ctrl+C again to force shutdown.");

        capture_sigterm().await;

        exit(130)
    });

    let (metrics, app, dns) = tokio::try_join!(metrics_server, app_server, dns_server)?;

    if let Err(e) = metrics {
        log::error!("metrics server crashed: {}", e);
    }

    if let Err(e) = app {
        log::error!("app server crashed: {}", e);
    }

    if let Err(e) = dns {
        log::error!("dns server crashed: {}", e);
    }

    Ok(())
}

async fn serve_metrics(
    recorder_handle: PrometheusHandle,
    settings: Settings,
    token: CancellationToken,
) -> Result<()> {
    let metrics_router = Router::new()
        .route("/metrics", get(move || ready(recorder_handle.render())))
        .fallback(notfound_404);

    let router = metrics_router.layer(CatchPanicLayer::custom(runtime::catch_panic));

    // Spawn tick-driven process collection task
    tokio::spawn(process::collect_metrics(
        settings.monitoring().process_collector_interval,
    ));

    let (server, _) = serve("Metrics", router, settings.server().metrics_port).await;

    token.cancelled().await;
    server.graceful_shutdown(None);

    Ok(())
}

async fn serve_app(settings: Settings, db_pool: Pool, token: CancellationToken) -> Result<()> {
    let req_id = HeaderName::from_static(REQUEST_ID);

    let app_state = AppState {
        db_pool: db_pool.clone(),
        verification_code_sender: Box::new(EmailVerificationCodeSender::new(
            settings.mailgun().clone(),
        )),
    };

    let router = router::setup_app_router(app_state)
        .route_layer(axum::middleware::from_fn(middleware::metrics::track))
        .layer(Extension(settings.environment()))
        // Include trace context as header into the response.
        .layer(response_with_trace_layer())
        // Opentelemetry tracing middleware.
        // This returns a `TraceLayer` configured to use
        // OpenTelemetry’s conventional span field names.
        .layer(opentelemetry_tracing_layer())
        // Set and propagate "request_id" (as a ulid) per request.
        .layer(
            ServiceBuilder::new()
                .set_request_id(req_id.clone(), MakeRequestUlid)
                .propagate_request_id(req_id),
        )
        // Applies the `tower_http::timeout::Timeout` middleware which
        // applies a timeout to requests.
        .layer(TimeoutLayer::new(Duration::from_millis(
            settings.server().timeout_ms,
        )))
        // Catches runtime panics and converts them into
        // `500 Internal Server` responses.
        .layer(CatchPanicLayer::custom(runtime::catch_panic))
        // Mark headers as sensitive on both requests and responses.
        .layer(SetSensitiveHeadersLayer::new([header::AUTHORIZATION]))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()));

    let (server, addr) = serve("Application", router, settings.server().port).await;

    if settings.healthcheck().is_enabled {
        tokio::spawn({
            let cancellation_token = token.clone();
            let settings = settings.healthcheck().clone();

            async move {
                let mut interval =
                    tokio::time::interval(Duration::from_millis(settings.interval_ms));

                let client = ClientBuilder::new(reqwest::Client::new())
                    .with(RetryTransientMiddleware::new_with_policy(
                        ExponentialBackoffBuilder::default()
                            .build_with_max_retries(settings.max_retries),
                    ))
                    .build();

                loop {
                    interval.tick().await;

                    if let Ok(response) = client
                        .get(&format!("http://{}/healthcheck", addr))
                        .send()
                        .await
                    {
                        if !response.status().is_success() {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                cancellation_token.cancel();

                log::error!("Healthcheck failed, shutting down");
            }
        });
    }

    token.cancelled().await;
    server.graceful_shutdown(None);

    Ok(())
}

async fn serve_dns(settings: Settings, db_pool: Pool, token: CancellationToken) -> Result<()> {
    let mut server = trust_dns_server::ServerFuture::new(dns::DBBackedAuthority::new(db_pool));

    let ip4_addr = Ipv4Addr::new(127, 0, 0, 1);
    let sock_addr = SocketAddrV4::new(ip4_addr, 1053);

    server.register_socket(UdpSocket::bind(sock_addr).await?);
    server.register_listener(
        TcpListener::bind(sock_addr).await?,
        Duration::from_millis(settings.server().timeout_ms),
    );

    tokio::select! {
        _ = server.block_until_done() => {},
        _ = token.cancelled() => {},
    };

    Ok(())
}

async fn serve(name: &str, app: Router, port: u16) -> (Handle, SocketAddr) {
    let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    info!(
        subject = "app_start",
        category = "init",
        "{} server listening on {}",
        name,
        bind_addr
    );

    let handle = Handle::new();

    tokio::spawn({
        let handle = handle.clone();
        async move {
            axum_server::bind(bind_addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
        }
    });

    let addr = handle.listening().await.unwrap();

    (handle, addr)
}

/// Captures and waits for system signals.
async fn capture_sigterm() {
    #[cfg(unix)]
    let term = async {
        signal(SignalKind::terminate())
            .expect("Failed to listen for SIGTERM")
            .recv()
            .await
    };

    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = signal::ctrl_c() => {},
        _ = term => {}
    };
}

/// Setup all [tracing][tracing] layers for storage, request/response tracing,
/// logging and metrics.
fn setup_tracing(
    writer: tracing_appender::non_blocking::NonBlocking,
    settings_otel: &Otel,
) -> Result<()> {
    let tracer = init_tracer(settings_otel)?;

    let registry = tracing_subscriber::Registry::default()
        .with(StorageLayer.with_filter(LevelFilter::TRACE))
        .with(
            tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_filter(LevelFilter::DEBUG)
                .with_filter(dynamic_filter_fn(|_metadata, ctx| {
                    !ctx.lookup_current()
                        // Exclude the rustls session "Connection" events
                        // which don't have a parent span
                        .map(|s| s.parent().is_none() && s.name() == "Connection")
                        .unwrap_or_default()
                })),
        )
        .with(LogFmtLayer::new(writer).with_target(true).with_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new(
                    std::env::var("RUST_LOG")
                        .unwrap_or_else(|_| "fission_server=info,tower_http=info,reqwest_retry=info,axum_tracing_opentelemetry=info".into()),
                )
            }),
        ))
        .with(
            MetricsLayer
                .with_filter(LevelFilter::TRACE)
                .with_filter(filter_fn(|metadata| {
                    // Filter and allow only:
                    // a) special metric prefix;
                    // b) any event
                    metadata.name().starts_with(METRIC_META_PREFIX) || metadata.is_event()
                })),
        );

    #[cfg(all(feature = "console", tokio_unstable))]
    #[cfg_attr(docsrs, doc(cfg(feature = "console")))]
    {
        let console_layer = console_subscriber::ConsoleLayer::builder()
            .retention(Duration::from_secs(60))
            .spawn();

        registry.with(console_layer).init();
    }

    #[cfg(any(not(feature = "console"), not(tokio_unstable)))]
    {
        registry.init();
    }

    Ok(())
}
