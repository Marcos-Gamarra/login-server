use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors;
mod login;

use crate::login::{RegistrationError, UserCredentials};

// Handle the registration request
async fn sign_up(
    State(pool): State<mysql_async::Pool>,
    Json(login_credentials): Json<UserCredentials>,
) -> impl IntoResponse {
    let mut body_message = std::collections::HashMap::new();
    if let Err(e) = login::insert_credentials(&pool, login_credentials).await {
        match e {
            RegistrationError::EmailAlreadyExists => {
                body_message.insert("error", "Email already exists");
                return (StatusCode::CONFLICT, Json(body_message));
            }
            RegistrationError::GenericError => {
                body_message.insert("error", "Generic error");
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(body_message));
            }
        }
    }

    body_message.insert("success", "User registered");
    (StatusCode::CREATED, Json(body_message))
}

// Handle the login request. Verify that the email and password are correct
async fn verify_credentials(
    State(pool): State<mysql_async::Pool>,
    Json(login_credentials): Json<UserCredentials>,
) -> impl IntoResponse {
    let mut body_message = std::collections::HashMap::new();
    if login::verify_credentials(&pool, login_credentials).await {
        body_message.insert("success", "User verified");
        return (StatusCode::OK, Json(body_message));
    }

    body_message.insert("error", "User not verified");
    (StatusCode::UNAUTHORIZED, Json(body_message))
}


//
async fn verify_email(
    State(pool): State<mysql_async::Pool>,
    Path((email, token)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut body_message = std::collections::HashMap::new();
    if login::verify_email(&pool, email, token).await {
        body_message.insert("success", "Email verified");
        return (StatusCode::OK, Json(body_message));
    }

    body_message.insert("error", "Email not verified");
    (StatusCode::UNAUTHORIZED, Json(body_message))
}

async fn test_verification_email(
    State(pool): State<mysql_async::Pool>,
    Json(user): Json<UserCredentials>,
) -> impl IntoResponse {
    login::register_unverified_email(&pool, user).await;

    (StatusCode::OK, "Email sent")
}

async fn test() -> impl IntoResponse {
    (StatusCode::OK, "Hello, world!")
}

#[tokio::main]
async fn main() {
    let pool = mysql_async::Pool::new("mysql://menutrack:hellothere@localhost:3306/MenutrackLogin");

    let app = Router::new()
        .route("/test", get(test))
        .route("/register_user", post(sign_up))
        .route("/verify_credentials", post(verify_credentials))
        .route("/test_verification_email", post(test_verification_email))
        .route("/verify_email/:email/:token", get(verify_email))
        .layer(
            cors::CorsLayer::new()
                .allow_origin(cors::Any)
                .allow_methods(cors::Any)
                .allow_headers(cors::Any),
        )
        .with_state(pool);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
