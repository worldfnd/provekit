use {
    axum::{
        extract::{DefaultBodyLimit, Json},
        response::IntoResponse,
        routing::{get, post},
        Router,
    },
    std::net::SocketAddr,
    tower::ServiceBuilder,
    tower_http::{
        cors::{Any, CorsLayer},
        timeout::TimeoutLayer,
        trace::TraceLayer,
    },
    tracing::info,
    tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt},
};

mod config;
mod error;
mod handlers;
mod models;
mod services;
mod state;

use {config::Config, handlers::verify_handler, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    init_tracing();

    let config = Config::from_env();
    let app_state = AppState::new(config.clone());

    info!(
        "Starting ProveKit Verifier Server v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Create the application router
    let app = create_app(config.clone()).with_state(app_state);

    // Bind to the configured address
    let addr = SocketAddr::new(
        config.server.host.parse().expect("Invalid host address"),
        config.server.port,
    );

    info!("Server listening on http://{}", addr);

    // Start the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Initialize structured logging with appropriate levels
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "verifier_server=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();
}

/// Create the Axum application with all routes and middleware
fn create_app(config: Config) -> Router<AppState> {
    Router::new()
        .route("/verify", post(verify_handler))
        .route("/health", get(health_check))
        .layer(
            ServiceBuilder::new()
                // Add request tracing
                .layer(TraceLayer::new_for_http())
                // Add CORS support
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
                // Add request timeout
                .layer(TimeoutLayer::new(config.server.request_timeout))
                // Limit request body size
                .layer(DefaultBodyLimit::max(config.server.max_request_size)),
        )
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
