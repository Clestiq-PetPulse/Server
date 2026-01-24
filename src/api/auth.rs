use crate::entities::user;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use serde_json::json;
use tower_cookies::{Cookie, Cookies};

#[derive(serde::Deserialize)]
pub struct RegisterRequest {
    email: String,
    password: String,
    name: String,
}

pub async fn register(
    Extension(db): Extension<DatabaseConnection>,
    Json(payload): Json<RegisterRequest>,
) -> Response {
    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to hash password"})),
            )
                .into_response()
        }
    };

    let now = chrono::Utc::now().naive_utc();
    let new_user = user::ActiveModel {
        email: Set(payload.email),
        password_hash: Set(password_hash),
        name: Set(payload.name),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    match new_user.insert(&db).await {
        Ok(user) => {
            tracing::info!(
                table = "users",
                action = "register_user",
                user_id = user.id,
                email = user.email,
                "User registered successfully"
            );
            (
                StatusCode::CREATED,
                Json(json!({"id": user.id, "email": user.email, "name": user.name})),
            )
                .into_response()
        },
        Err(e) => {
            // Check for duplicate key error (Postgres code 23505)
            let error_msg = e.to_string();
            if error_msg.contains("duplicate key value violates unique constraint") {
                 tracing::warn!(
                    table = "users",
                    action = "register_user_failed",
                    reason = "duplicate_email",
                    error = ?e,
                    "Registration failed: duplicate email"
                );
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "Email already exists"})),
                ).into_response();
            }

            tracing::error!(
                table = "users",
                action = "register_user_error",
                error = ?e,
                "Registration failed: database error"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        },
    }
}

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

pub async fn login(
    Extension(db): Extension<DatabaseConnection>,
    cookies: Cookies,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let user = match user::Entity::find()
        .filter(user::Column::Email.eq(payload.email.clone()))
        .one(&db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid email or password"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Invalid password hash in DB"})),
            )
                .into_response()
        }
    };

    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        // Set Cookie
        let mut cookie = Cookie::new("petpulse_user", user.id.to_string());
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookies.add(cookie);

        tracing::info!(
            table = "users",
            action = "login_user",
            user_id = user.id,
            email = user.email,
            "User logged in successfully"
        );

        (StatusCode::OK, Json(json!({"message": "Login successful"}))).into_response()
    } else {
        tracing::warn!(
            table = "users",
            action = "login_user_failed",
            reason = "invalid_credentials",
            email = payload.email,
            "Login failed: invalid password"
        );
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid email or password"})),
        )
            .into_response()
    }
}
