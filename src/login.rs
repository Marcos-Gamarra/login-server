use crate::entity::password_table;
use crate::entity::unverified_emails::{self, Entity as UnverifiedEmails};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use rand::distributions::{Alphanumeric, DistString};
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::{NotSet, Set},
    EntityTrait, TransactionTrait,
};
use serde::{Deserialize, Serialize};

//takes the password and a salt and returns the hash of the password + salt
pub fn hashing(password: String, salt: &SaltString) -> String {
    let argon2_instance = Argon2::default();

    let hash_as_string = argon2_instance
        .hash_password(password.as_bytes(), salt)
        .unwrap()
        .to_string();

    hash_as_string
}

#[derive(Serialize, Deserialize)]
pub struct UserCredentials {
    pub email: String,
    pub password: String,
}

#[derive(Debug)]
pub enum EmailVerificationError {
    TokenMismatch,
    EmailNotFound,
    DatabaseError,
}

//function to verify a user's password.
//It takes a connection pool and a LoginCredentials struct.
//It picks a connection from the pool and fetches the password hash and salt from the database.
//It hashes the password using the salt and compares it with the hash.
//It returns true if the password is correct and false otherwise.
pub async fn verify_credentials(
    db_conn_pool: &sea_orm::DatabaseConnection,
    credentials: UserCredentials,
) -> bool {
    let Ok(query_result) = UnverifiedEmails::find_by_id(credentials.email)
        .one(db_conn_pool)
        .await else {
            return false;
        };

    if let Some(row) = query_result {
        let argon2_instance = Argon2::default();
        let salt = SaltString::from_b64(&row.salt).unwrap();
        let hash = argon2_instance
            .hash_password(credentials.password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        if hash == row.hash {
            return true;
        }
    }

    false
}

//generates a random token of 16 bytes
fn generate_verification_token() -> String {
    let token = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
    token
}

//generates the body of the verification email
//it takes the unique token and adds it to the verification link
fn generate_verification_email_body(email: &str, token: String) -> String {
    format!(
        "
        <html>
            <body>
                <p>
                    <a href=\"https://marcosgamarra.ninja/verify_email/{email}/{token}\">
                        Click here to verify email
                    </a>
                </p>
            </body>
        </html>
        "
    )
}

async fn send_verification_email(email: String) {
    use lettre::{message::header::ContentType, Message, SmtpTransport, Transport};

    let token = generate_verification_token();
    let body = generate_verification_email_body(&email, token);
    let to = format!("Hello <{}>", email);

    let email = Message::builder()
        .from("Marcos <marcos@marcosgamarra.ninja>".parse().unwrap())
        .to(to.parse().unwrap())
        .subject("Verification email")
        .header(ContentType::TEXT_HTML)
        .body(body)
        .unwrap();

    let mailer = SmtpTransport::unencrypted_localhost();
    let result = mailer.send(&email);

    if let Err(e) = result {
        println!("Could not send email: {}", e);
    }
}

pub async fn handle_email_verification_attemp(
    db_conn_pool: &sea_orm::DatabaseConnection,
    email: String,
    token: String,
) -> Result<(), EmailVerificationError> {
    let query_result = UnverifiedEmails::find_by_id(email.clone())
        .one(db_conn_pool)
        .await;

    let retrieved_row = match query_result {
        Ok(Some(row)) => row,
        Ok(None) => return Err(EmailVerificationError::EmailNotFound),
        Err(_) => return Err(EmailVerificationError::DatabaseError),
    };

    if retrieved_row.token == token {
        return handle_successful_email_verification(db_conn_pool, retrieved_row.into())
            .await
            .or_else(|_| Err(EmailVerificationError::DatabaseError));
    } else {
        return Err(EmailVerificationError::TokenMismatch);
    }
}

pub async fn handle_successful_email_verification(
    db_conn_pool: &sea_orm::DatabaseConnection,
    unverified_email: unverified_emails::ActiveModel,
) -> Result<(), sea_orm::DbErr> {
    let user_credentials = password_table::ActiveModel {
        email: unverified_email.email.clone(),
        hash: unverified_email.hash.clone(),
        salt: unverified_email.salt.clone(),
        ..Default::default()
    };

    db_conn_pool
        .transaction::<_, (), sea_orm::DbErr>(|conn| {
            Box::pin(async move {
                user_credentials.insert(conn).await?;
                unverified_email.delete(conn).await?;
                Ok(())
            })
        })
        .await
        .or(Err(sea_orm::DbErr::Custom(
            "Transaction failed".to_string(),
        )))
}

pub async fn handle_sign_up_request(
    db_conn_pool: &sea_orm::DatabaseConnection,
    user: UserCredentials,
) -> Result<(), sea_orm::error::DbErr> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hashing(user.password, &salt);
    let token = generate_verification_token();

    let unverified_email = unverified_emails::ActiveModel {
        email: Set(user.email.clone()),
        hash: Set(hash),
        salt: Set(salt.to_string()),
        token: Set(token),
        expires: NotSet,
    };

    if let Err(e) = unverified_email.insert(db_conn_pool).await {
        println!("Could not insert unverified email: {}", e);
        return Err(e);
    };

    send_verification_email(user.email).await;
    Ok(())
}
