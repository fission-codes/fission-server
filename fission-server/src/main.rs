//! fission-server

use anyhow::{anyhow, Result};
use axum::{extract::Extension, headers::HeaderName, routing::get, Router};
use axum_server::Handle;
use axum_tracing_opentelemetry::middleware::{OtelAxumLayer, OtelInResponseLayer};
use clap::Parser;
use config::{Config, Environment};
use ed25519::pkcs8::{spki::der::pem::LineEnding, DecodePrivateKey, EncodePrivateKey};
use fission_core::{ed_did_key::EdDidKey, serde_value_source::SerdeValueSource};
use fission_server::{
    app_state::{AppState, AppStateBuilder},
    db::{self, Pool},
    dns::server::DnsServer,
    docs::ApiDoc,
    metrics::{process, prom::setup_metrics_recorder},
    middleware::{self, request_ulid::MakeRequestUlid, runtime},
    router,
    routes::{fallback::notfound_404, ws::WsPeerMap},
    settings::{AppEnvironment, Otel, Settings},
    setups::{
        local::{LocalSetup, WebsocketCodeSender},
        prod::{EmailVerificationCodeSender, IpfsHttpApiDatabase, ProdSetup},
        ServerSetup,
    },
    test_utils::ephermeral_db::{create_ephermeral_db, destroy_ephermeral_db},
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
use serde::{Deserialize, Serialize};
use std::{
    future::ready,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    process::exit,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs,
    io::AsyncReadExt,
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
use url::Url;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Request identifier field.
const REQUEST_ID: &str = "request_id";

#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
#[command(name = "fission-server")]
#[command(about = "Run the fission server")]
struct Cli {
    #[arg(long, short = 'c', help = "Path to the settings.toml")]
    config_path: Option<PathBuf>,
    #[arg(
        long,
        help = "Whether to turn off ansi terminal colors in log messages"
    )]
    no_colors: bool,
    #[arg(
        long,
        help = "Enable shutdown via closed stdin pipe. This is useful for shutting down if spawned from a parent binary, if that binary closes and pipes stdin."
    )]
    close_on_stdin_close: bool,
    #[arg(
        long,
        help = "Use an ephemeral DB that is destroyed before existing the process. Useful for integration tests."
    )]
    ephemeral_db: bool,
    #[arg(
        long,
        help = "Generate a private key at the keypair path defined in the settings, if necessary."
    )]
    gen_key_if_needed: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load parameters from both CLI & environment variables
    let cli: Cli = Config::builder()
        .add_source(SerdeValueSource::from(Cli::parse()))
        .add_source(
            Environment::with_prefix("FISSION_SERVER")
                .separator("__")
                .try_parsing(true),
        )
        .build()?
        .try_deserialize()?;

    let settings = Settings::load(cli.config_path.clone())?;

    let (stdout_writer, _stdout_guard) = tracing_appender::non_blocking(io::stdout());
    setup_tracing(stdout_writer, &settings.otel, !cli.no_colors)?;

    info!(
        subject = "cli_settings",
        category = "init",
        ?cli,
        "loaded CLI settings"
    );

    info!(
        subject = "app_settings",
        category = "init",
        ?settings,
        "starting server",
    );

    let (db_pool, ephemeral_db) = if cli.ephemeral_db {
        let mut url = Url::from_str(&settings.database.url)?;
        url.set_path("");
        let eph_db = create_ephermeral_db(url.as_str(), "cli_ephemeral")?;
        url.set_path(&eph_db);
        (
            db::pool(url.as_str(), settings.database.connect_timeout).await?,
            Some(eph_db),
        )
    } else {
        (
            db::pool(&settings.database.url, settings.database.connect_timeout).await?,
            None,
        )
    };

    let server_keypair = load_keypair(&settings, cli.gen_key_if_needed).await?;

    match settings.server.environment {
        AppEnvironment::Staging | AppEnvironment::Prod => {
            let app_state = setup_prod_app_state(&settings, db_pool, server_keypair).await?;
            run_with_app_state(cli, settings, app_state, ephemeral_db).await
        }
        AppEnvironment::Local | AppEnvironment::Dev => {
            let app_state = setup_local_app_state(&settings, db_pool, server_keypair).await?;
            run_with_app_state(cli, settings, app_state, ephemeral_db).await
        }
    }
}

async fn run_with_app_state<S: ServerSetup + 'static>(
    cli: Cli,
    settings: Settings,
    app_state: AppState<S>,
    ephemeral_db: Option<String>,
) -> Result<()> {
    let dns_server = app_state.dns_server.clone();
    let recorder_handle = setup_metrics_recorder()?;
    let cancellation_token = CancellationToken::new();

    let metrics_server = tokio::spawn(serve_metrics(
        recorder_handle,
        settings.clone(),
        cancellation_token.clone(),
    ));

    let app_server = tokio::spawn(serve_app(
        app_state,
        settings.clone(),
        cancellation_token.clone(),
    ));

    let dns_server = tokio::spawn(serve_dns(
        settings.clone(),
        dns_server,
        cancellation_token.clone(),
    ));

    if cli.close_on_stdin_close {
        // This is why: https://matklad.github.io/2023/10/11/unix-structured-concurrency.html

        tracing::info!("Enabling closing on piped stdin");

        let cancellation_token = cancellation_token.clone();

        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buffer = [0u8; 1024];
            loop {
                let Ok(bytes_read) = stdin.read(&mut buffer).await else {
                    println!("stdin failed, shutting down.");
                    cancellation_token.cancel();
                    break;
                };

                if bytes_read == 0 {
                    println!("stdin closed, shutting down.");
                    cancellation_token.cancel();
                    break;
                }
            }
        });
    }

    tokio::spawn(async move {
        capture_sigterm().await;

        cancellation_token.cancel();
        println!("\nCtrl+C received, shutting down. Press Ctrl+C again to force shutdown.");

        capture_sigterm().await;

        println!("Shutdown forced.");

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

    if let Some(db_name) = ephemeral_db {
        let mut base_url = Url::from_str(&settings.database.url)?;
        base_url.set_path("");
        destroy_ephermeral_db(base_url.as_str(), &db_name)?;
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
        settings.monitoring.process_collector_interval,
    ));

    let (server, _) = serve("Metrics", router, settings.server.metrics_port).await?;

    token.cancelled().await;
    server.graceful_shutdown(None);

    Ok(())
}

async fn setup_prod_app_state(
    settings: &Settings,
    db_pool: Pool,
    server_keypair: EdDidKey,
) -> Result<AppState<ProdSetup>> {
    let dns_server = DnsServer::new(&settings.dns, db_pool.clone(), server_keypair.did())?;

    let app_state = AppStateBuilder::<ProdSetup>::default()
        .with_dns_settings(settings.dns.clone())
        .with_db_pool(db_pool)
        .with_ipfs_peers(settings.ipfs.peers.clone())
        .with_verification_code_sender(EmailVerificationCodeSender::new(settings.mailgun.clone()))
        .with_ipfs_db(IpfsHttpApiDatabase::default())
        .with_server_keypair(server_keypair)
        .with_dns_server(dns_server)
        .finalize()?;

    Ok(app_state)
}

async fn setup_local_app_state(
    settings: &Settings,
    db_pool: Pool,
    server_keypair: EdDidKey,
) -> Result<AppState<LocalSetup>> {
    let dns_server = DnsServer::new(&settings.dns, db_pool.clone(), server_keypair.did())?;

    let ws_peer_map = Arc::new(WsPeerMap::default());

    let app_state = AppStateBuilder::<LocalSetup>::default()
        .with_dns_settings(settings.dns.clone())
        .with_db_pool(db_pool)
        .with_ipfs_peers(settings.ipfs.peers.clone())
        .with_ws_peer_map(Arc::clone(&ws_peer_map))
        .with_verification_code_sender(WebsocketCodeSender::new(ws_peer_map))
        .with_ipfs_db(IpfsHttpApiDatabase::default())
        .with_server_keypair(server_keypair)
        .with_dns_server(dns_server)
        .finalize()?;

    Ok(app_state)
}

async fn serve_app<S: ServerSetup + 'static>(
    app_state: AppState<S>,
    settings: Settings,
    token: CancellationToken,
) -> Result<()> {
    let req_id = HeaderName::from_static(REQUEST_ID);

    let router = router::setup_app_router(app_state)
        .route_layer(axum::middleware::from_fn(middleware::metrics::track))
        .layer(Extension(settings.server.environment))
        // Include trace context as header into the response.
        .layer(OtelInResponseLayer)
        // Opentelemetry tracing middleware.
        // This returns a `TraceLayer` configured to use
        // OpenTelemetry’s conventional span field names.
        .layer(OtelAxumLayer::default())
        // Set and propagate "request_id" (as a ulid) per request.
        .layer(
            ServiceBuilder::new()
                .set_request_id(req_id.clone(), MakeRequestUlid)
                .propagate_request_id(req_id),
        )
        // Applies the `tower_http::timeout::Timeout` middleware which
        // applies a timeout to requests.
        .layer(TimeoutLayer::new(Duration::from_millis(
            settings.server.timeout_ms,
        )))
        // Catches runtime panics and converts them into
        // `500 Internal Server` responses.
        .layer(CatchPanicLayer::custom(runtime::catch_panic))
        // Mark headers as sensitive on both requests and responses.
        .layer(SetSensitiveHeadersLayer::new([header::AUTHORIZATION]))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()));

    let (server, addr) = serve("Application", router, settings.server.port).await?;

    if settings.healthcheck.is_enabled {
        tokio::spawn({
            let cancellation_token = token.clone();
            let settings = settings.healthcheck.clone();

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

async fn serve_dns(
    settings: Settings,
    dns_server: DnsServer,
    token: CancellationToken,
) -> Result<()> {
    let mut server = hickory_server::ServerFuture::new(dns_server);

    let ip4_addr = Ipv4Addr::new(127, 0, 0, 1);
    let sock_addr = SocketAddrV4::new(ip4_addr, settings.dns.server_port);

    server.register_socket(UdpSocket::bind(sock_addr).await?);
    server.register_listener(
        TcpListener::bind(sock_addr).await?,
        Duration::from_millis(settings.server.timeout_ms),
    );

    tokio::select! {
        _ = server.block_until_done() => {
            info!("Background tasks for DNS server all terminated.")
        },
        _ = token.cancelled() => {},
    };

    Ok(())
}

async fn serve(name: &str, app: Router, port: u16) -> Result<(Handle, SocketAddr)> {
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

    let addr = handle.listening().await.ok_or_else(|| {
        anyhow!(
            "Couldn't bind server to address {bind_addr:?}, perhaps the port is already in use?"
        )
    })?;

    Ok((handle, addr))
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
    colors: bool,
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
        .with(LogFmtLayer::new(writer).with_target(true).with_ansi(colors).with_filter(
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

async fn load_keypair(settings: &Settings, gen_key_if_needed: bool) -> Result<EdDidKey> {
    let pem_path = settings.relative_keypair_path();

    if !pem_path.exists() && gen_key_if_needed {
        let server_keypair = EdDidKey::generate();
        let pem = server_keypair.to_pkcs8_pem(LineEnding::default())?;
        fs::write(&pem_path, pem).await?;
        tracing::info!(%server_keypair, ?pem_path, "Missing sever keypair, generated a new one and stored");
        return Ok(server_keypair);
    }

    let server_keypair = fs::read_to_string(&pem_path)
        .await
        .map_err(|e| anyhow!(e))
        .and_then(|pem| EdDidKey::from_pkcs8_pem(&pem).map_err(|e| anyhow!(e)))
        .map_err(|e| anyhow!("Couldn't load server DID from {}: {}. Make sure to generate a key by running `openssl genpkey -algorithm ed25519 -out {}`", pem_path.to_string_lossy(), e, pem_path.to_string_lossy()))?;

    tracing::info!(%server_keypair, "Loaded server DID");

    Ok(server_keypair)
}
