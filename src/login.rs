use crate::entity::password_table;
use crate::entity::unverified_emails::{self, Entity as UnverifiedEmails};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use rand::distributions::{Alphanumeric, DistString};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ActiveModelTrait, EntityTrait};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserCredentials {
    email: String,
    password: String,
}

//takes the password and a salt and return the hash of the password + salt
pub fn hashing(password: String, salt: &SaltString) -> String {
    let argon2_instance = Argon2::default();

    let hash_as_string = argon2_instance
        .hash_password(password.as_bytes(), salt)
        .unwrap()
        .to_string();

    hash_as_string
}

//function to insert a new user into the database.
//It takes a connection pool and a LoginCredentials struct.
//It generates a salt and hashes the password using argon2.
//It picks a connection from the pool and inserts the email and hashed password into the database.
//It returns a Result with a unit type on success and a RegistrationError on failure.
pub async fn insert_credentials(
    db_conn_pool: &sea_orm::DatabaseConnection,
    user: UserCredentials,
) -> Result<(), sea_orm::error::DbErr> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hashing(user.password, &salt);

    let user_credentials = password_table::ActiveModel {
        email: Set(user.email),
        password_hash: Set(hash),
        password_salt: Set(salt.to_string()),
        ..Default::default()
    };

    if let Err(e) = user_credentials.insert(db_conn_pool).await {
        return Err(e);
    }

    Ok(())
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
            <p><a href=\"https://marcosgamarra.ninja/verify_email/{email}/{token}\">Click here to visit verify email</a></p>
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

pub async fn verify_email(
    db_conn_pool: &sea_orm::DatabaseConnection,
    email: String,
    token: String,
) -> bool {
    if let Ok(query_result) = UnverifiedEmails::find_by_id(email.clone())
        .one(db_conn_pool)
        .await
    {
        if let Some(retrieved_row) = query_result {
            if retrieved_row.token == token {
                return true;
            }
        }
    }

    false
}

pub async fn insert_unverified_email(
    db_conn_pool: &sea_orm::DatabaseConnection,
    user: UserCredentials,
) -> Result<(), sea_orm::error::DbErr> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hashing(user.password, &salt);
    let token = generate_verification_token();

    let unverified_email_to_insert = unverified_emails::ActiveModel {
        email: Set(user.email.clone()),
        hash: Set(hash),
        salt: Set(salt.to_string()),
        token: Set(token),
        expires: NotSet,
    };

    if let Err(e) = unverified_email_to_insert.insert(db_conn_pool).await {
        println!("Could not insert unverified email: {}", e);
        return Err(e);
    };

    send_verification_email(user.email).await;
    Ok(())
}
