use rand::distributions::{Alphanumeric, DistString};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use mysql_async::prelude::*;
use serde::{Deserialize, Serialize};

pub enum RegistrationError {
    EmailAlreadyExists,
    GenericError,
}

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
pub async fn insert_credentials<'a>(
    pool: &mysql_async::Pool,
    user: UserCredentials,
) -> Result<(), RegistrationError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hashing(user.password, &salt);

    let mut conn = pool.get_conn().await.unwrap();

    let query = format!(
        "insert into password_table (email, password_hash, password_salt) values ('{}', '{}' , '{}')",
        user.email, hash, salt
    );

    if let Err(e) = conn.query_drop(query).await {
        if let mysql_async::Error::Server(e) = e {
            if e.code == 1062 {
                return Err(RegistrationError::EmailAlreadyExists);
            }
        } else {
            return Err(RegistrationError::GenericError);
        }
    }

    Ok(())
}

//function to verify a user's password.
//It takes a connection pool and a LoginCredentials struct.
//It picks a connection from the pool and fetches the password hash and salt from the database.
//It hashes the password using the salt and compares it with the hash.
//It returns true if the password is correct and false otherwise.
pub async fn verify_credentials(pool: &mysql_async::Pool, credentials: UserCredentials) -> bool {
    let mut conn = pool.get_conn().await.unwrap();
    let query = format!(
        "select password_hash, password_salt from password_table where email = '{}'",
        credentials.email
    );

    let result = conn
        .query_first::<(String, String), String>(query)
        .await
        .unwrap();

    if let Some((target_hash, salt)) = result {
        let argon2_instance = Argon2::default();
        let salt = SaltString::from_b64(&salt).unwrap();
        let hash = argon2_instance
            .hash_password(credentials.password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        if hash == target_hash {
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

pub async fn verify_email(pool: &mysql_async::Pool, email: String, token: String) -> bool {
    let mut conn = pool.get_conn().await.unwrap();
    let query = format!("select token from unverified_emails where email = '{email}'");

    let result = conn.query_first::<String, String>(query).await.unwrap();

    if let Some(retrieved_token) = result {
        if retrieved_token == token {
            return true;
        }
    }

    false
}

pub async fn register_unverified_email<'a>(pool: &mysql_async::Pool, user: UserCredentials) {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hashing(user.password, &salt);
    let token = generate_verification_token();

    let mut conn = pool.get_conn().await.unwrap();

    let query = format!(
        "insert into unverified_emails (email, hash, salt, token) values ('{}', '{}' , '{}', '{}')",
        user.email, hash, salt, token
    );

    conn.query_drop(query).await.unwrap();

    send_verification_email(user.email).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashing() {
        let salt = SaltString::generate(&mut OsRng);
        let hash = hashing("password".to_string(), &salt);
        assert_eq!(hash.len(), 97);
    }
}
