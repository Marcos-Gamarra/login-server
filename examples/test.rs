use lettre::{Message, SmtpTransport, Transport};

fn main() {
    let email = Message::builder()
        .from("Marcos <marcos@marcosgamarra.ninja>".parse().unwrap())
        .to("Hei <marcos.gamarra12345@gmail.com>".parse().unwrap())
        .subject("Happy new year")
        .body(String::from("Be happy!"))
        .unwrap();

    let sender = SmtpTransport::unencrypted_localhost();

    sender.send(&email).unwrap();

    if let Err(e) = sender.test_connection() {
        eprintln!("Could not connect to server: {:?}", e);
        return;
    } else {
        println!("Connection successful");
    }
}
