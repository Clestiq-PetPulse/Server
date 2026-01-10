use axum::{
    routing::{get, post},
    Router, Extension,
};
use sea_orm::{Database, DatabaseConnection};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod entities;
mod migrator;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Database Connection
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = Database::connect(&database_url).await.expect("Failed to connect to database");

    // Run migrations
    use sea_orm_migration::MigratorTrait;
    migrator::Migrator::up(&db, None).await.expect("Failed to run migrations");

    // Use app logic directly here
    let app = app(db);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}

fn app(db: DatabaseConnection) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(api::auth::register))
        .route("/login", post(api::auth::login));

    let protected_routes = Router::new()
        .route("/users", get(api::user::get_user).patch(api::user::update_user).delete(api::user::delete_user))
        .route("/pets", post(api::pet::create_pet))
        .route("/pets/:id", get(api::pet::get_pet).patch(api::pet::update_pet).delete(api::pet::delete_pet))
        .route_layer(axum::middleware::from_fn(api::middleware::auth_middleware));

    Router::new()
        .route("/health", get(health_check))
        .merge(auth_routes)
        .merge(protected_routes)
        .layer(Extension(db))
        .layer(tower_cookies::CookieManagerLayer::new())
}
