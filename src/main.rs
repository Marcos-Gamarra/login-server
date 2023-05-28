use crate::entity::unverified_emails::Entity as UnverifiedEmails;
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use sea_orm::entity::*;
use sea_orm::DatabaseConnection;
use std::net::SocketAddr;
use tower_http::cors;

use crate::login::UserCredentials;

mod entity;
mod login;
// Handle the registration request
async fn sign_up(
    State(db_conn_pool): State<sea_orm::DatabaseConnection>,
    Json(login_credentials): Json<UserCredentials>,
) -> impl IntoResponse {
    let mut body_message = std::collections::HashMap::new();
    if let Err(_) = login::handle_sign_up_request(&db_conn_pool, login_credentials).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(body_message));
    }

    body_message.insert("success", "User registered");
    (StatusCode::CREATED, Json(body_message))
}

// Handle the login request. Verify that the email and password are correct
async fn verify_credentials(
    State(db_conn_pool): State<sea_orm::DatabaseConnection>,
    Json(login_credentials): Json<UserCredentials>,
) -> impl IntoResponse {
    let mut body_message = std::collections::HashMap::new();
    if login::verify_credentials(&db_conn_pool, login_credentials).await {
        body_message.insert("success", "User verified");
        return (StatusCode::OK, Json(body_message));
    }

    body_message.insert("error", "User not verified");
    (StatusCode::UNAUTHORIZED, Json(body_message))
}

//
async fn verify_email(
    State(db_conn_pool): State<sea_orm::DatabaseConnection>,
    Path((email, token)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut body_message = std::collections::HashMap::new();
    if let Ok(_) = login::handle_email_verification_attemp(&db_conn_pool, email, token).await {
        body_message.insert("success", "Email verified");
        return (StatusCode::OK, Json(body_message));
    }

    body_message.insert("error", "Email not verified");
    (StatusCode::UNAUTHORIZED, Json(body_message))
}

async fn test_verification_email(
    State(db_conn_pool): State<sea_orm::DatabaseConnection>,
    Json(user): Json<UserCredentials>,
) -> impl IntoResponse {
    if let Err(_) = login::handle_sign_up_request(&db_conn_pool, user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, "error");
    }

    (StatusCode::OK, "Email sent")
}

async fn test(State(db_conn_pool): State<DatabaseConnection>) -> impl IntoResponse {
    let email = UnverifiedEmails::find().one(&db_conn_pool).await.unwrap();
    if let Some(email) = email {
        println!("Email: {}", email.email);
    }
    (StatusCode::OK, "Hello, world!")
}

#[tokio::main]
async fn main() {
    //read DATABASE_URL env variable
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_conn_pool: DatabaseConnection = sea_orm::Database::connect(db_url).await.unwrap();

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
        .with_state(db_conn_pool);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
