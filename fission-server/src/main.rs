//! fission-server

use anyhow::Result;

use axum::{extract::Extension, headers::HeaderName, routing::get, Router};
use axum_tracing_opentelemetry::{opentelemetry_tracing_layer, response_with_trace_layer};
use fission_server::{
    db,
    dns::handler::Handler,
    docs::ApiDoc,
    metrics::{process, prom::setup_metrics_recorder},
    middleware::{self, logging::Logger, request_ulid::MakeRequestUlid, runtime},
    router::{self, AppState},
    routes::fallback::notfound_404,
    settings::{Otel, Settings},
    tracer::init_tracer,
    tracing_layers::{
        format_layer::LogFmtLayer,
        metrics_layer::{MetricsLayer, METRIC_META_PREFIX},
        storage_layer::StorageLayer,
    },
};
use futures::Future;
use http::header;
use reqwest_middleware::ClientBuilder;
use reqwest_retry::RetryTransientMiddleware;
use reqwest_tracing::TracingMiddleware;
use retry_policies::policies::ExponentialBackoffBuilder;
use std::{
    future::ready,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    signal::{
        self,
        unix::{signal, SignalKind},
    },
    sync::{broadcast, oneshot},
};
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
use trust_dns_server::ServerFuture;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Request identifier field.
const REQUEST_ID: &str = "request_id";

#[tokio::main]
async fn main() -> Result<()> {
    let (stdout_writer, _stdout_guard) = tracing_appender::non_blocking(io::stdout());

    let settings = Settings::load()?;
    setup_tracing(stdout_writer, settings.otel())?;

    info!(
        subject = "app_settings",
        category = "init",
        "starting with settings: {:?}",
        settings,
    );

    let env = settings.environment();
    let recorder_handle = setup_metrics_recorder()?;
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    let app_metrics = async {
        let metrics_router = Router::new()
            .route("/metrics", get(move || ready(recorder_handle.render())))
            .fallback(notfound_404);

        let router = metrics_router.layer(CatchPanicLayer::custom(runtime::catch_panic));

        // Spawn tick-driven process collection task
        tokio::task::spawn(process::collect_metrics(
            settings.monitoring().process_collector_interval,
        ));

        serve(
            "Metrics",
            router,
            settings.server().metrics_port,
            shutdown(shutdown_rx),
        )
        .await
    };

    let app = async {
        let req_id = HeaderName::from_static(REQUEST_ID);
        let db_pool = db::pool().await?;

        let app_state = AppState {
            db_pool: db_pool.clone(),
            db_version: db::schema_version(&mut db::connect(&db_pool).await?).await?,
        };

        let router = router::setup_app_router(app_state)
            .route_layer(axum::middleware::from_fn(middleware::metrics::track))
            .layer(Extension(env))
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

        serve(
            "Application",
            router,
            settings.server().port,
            shutdown_with_healthcheck(shutdown_tx, &settings),
        )
        .await
    };

    let dns_server = async {
        let mut server = ServerFuture::new(Handler::new());
        let ip4_addr = Ipv4Addr::new(127, 0, 0, 1);
        let sock_addr = SocketAddrV4::new(ip4_addr, 1053);
        server.register_socket(UdpSocket::bind(sock_addr).await?);
        server.register_listener(
            TcpListener::bind(sock_addr).await?,
            Duration::from_millis(settings.server().timeout_ms),
        );
        server.block_until_done().await?;

        Ok(())
    };

    tokio::try_join!(app, app_metrics, dns_server)?;
    Ok(())
}

async fn serve<F>(name: &str, app: Router, port: u16, shutdown_handler: F) -> Result<()>
where
    F: Future<Output = ()>,
{
    let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    info!(
        subject = "app_start",
        category = "init",
        "{} server listening on {}",
        name,
        bind_addr
    );

    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_handler)
        .await?;

    Ok(())
}

/// Captures and waits for system signals.
async fn shutdown(mut shutdown_rx: broadcast::Receiver<()>) {
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
        _ = signal::ctrl_c() => {}
        _ = term => {}
        _ = shutdown_rx.recv() => {}
    }
}

async fn shutdown_with_healthcheck(shutdown_tx: broadcast::Sender<()>, settings: &Settings) {
    let shutdown_rx = shutdown_tx.subscribe();
    let shutdown = async { shutdown(shutdown_rx).await };
    let (health_tx, health_rx) = oneshot::channel::<()>();

    tokio::task::spawn({
        let port = settings.server().port;
        let settings = settings.healthcheck().clone();

        async move {
            if !settings.is_enabled {
                return;
            }

            let mut interval = tokio::time::interval(Duration::from_millis(settings.interval_ms));

            let client = ClientBuilder::new(reqwest::Client::new())
                .with(TracingMiddleware::default())
                .with(Logger)
                .with(RetryTransientMiddleware::new_with_policy(
                    ExponentialBackoffBuilder::default()
                        .build_with_max_retries(settings.max_retries),
                ))
                .build();

            loop {
                interval.tick().await;

                if let Ok(response) = client
                    .get(&format!("http://localhost:{}/healthcheck", port))
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

            health_tx.send(()).unwrap();
        }
    });

    tokio::select! {
        _ = shutdown => {}
        Ok(()) = health_rx => {
            log::error!("Healthcheck failed, shutting down");

            shutdown_tx.send(()).unwrap();
        }
    }
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
