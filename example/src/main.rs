use std::error::Error;
use axial::core::servers::HttpError;
use axial_macros::{get, post, put};
use axial::core::routes::router::{Responder, Response};
use axial::core::servers::http::{HttpServer, ServerTrait};
use axial::core::routes::router::Request;
use axial::core::clients::http::{Client, HttpClient};

async fn client() -> String {
    let client = HttpClient::new()
        .timeout(Some(std::time::Duration::from_secs(5)))
        .user_agent(Some(axial::core::clients::http::USER_AGENT_CHROME.to_string()))
        .header("X-Custom-Header", "value")
        .build()
        .unwrap();

    let response = client.get("https://google.com/").await.unwrap();

    response
}

#[get("/user/{id}")]
async fn hello_world(_: Request) -> impl Responder {
    Response::new(200).body("Hello, World!")
}

#[post("/user/{id}")]
async fn post_user_details(req: Request) -> Result<Response, HttpError> {
    let user_id_str = req.path_params.get("id").cloned().unwrap_or_default();
    let version_str = req.query_param("version")?;

    let mut response_body = format!("User ID: {}", user_id_str);
    response_body.push_str(&format!(", Version (from query): {}", version_str));

    Ok(Response::new(201).body(response_body).header("Content-Type", "application/json"))
}

#[put("/user/{id}")]
async fn put_user_details(req: Request) -> impl Responder {
    let user_id_str = req.path_params.get("id").cloned().unwrap_or_default();
    let version_str = req.query_param("version");

    let mut response_body = format!("User ID: {}", user_id_str);
    response_body.push_str(&format!(", Version (from query): {}", version_str.unwrap_or_default()));

    Response::new(200).body(response_body).header("Content-Type", "application/json")
}

#[tokio::main]
async fn main() {
    let response = client().await;

    println!("Response from client: {}", response);

    if let Err(e) = example_crypto() {
        eprintln!("Error: {}", e);
    }

    HttpServer::new(String::from("127.0.0.1"), 9093)
        .settings(|s| {
            s.keep_alive(true);
            s.max_connections(10000);
            s.timeout(std::time::Duration::from_secs(30));
        })
        .service(hello_world)
        .service(post_user_details)
        .service(put_user_details)
        .start()
        .await.unwrap();
}

fn example_crypto() -> Result<(), Box<dyn Error>> {
    println!("Example of hybrid encryption using Axial framework with Kyber KEM");

    let bob_keypair = axial::pqcrypto::pq_kem_keypair();

    let bob_public = axial::crypto::SecureKey::new(bob_keypair.public.clone(), axial::crypto::KeyType::KyberPublic)?;
    let bob_private = axial::crypto::SecureKey::new(bob_keypair.secret.clone(), axial::crypto::KeyType::KyberPrivate)?;

    let message = "Super Secret Message";
    let metadata = b"From: Alice, Date: 2025-05-20";
    
    let (kyber_ciphertext, encrypted_data) = bob_public.with_key(|public_key| {
        axial::crypto::HybridCrypto::encrypt(public_key, message, Some(metadata))
    })?;
    
    println!("Message encrypted successfully!");

    let (decrypted_message, received_metadata) = bob_private.with_key(|private_key| {
        axial::crypto::HybridCrypto::decrypt(private_key, &kyber_ciphertext, &encrypted_data, true)
    })?;
    
    println!("Message: {}", decrypted_message);
    println!("Metadata: {}", String::from_utf8_lossy(
        &received_metadata.clone().unwrap_or_default()
    ));

    assert_eq!(message, decrypted_message);
    assert_eq!(metadata, &received_metadata.unwrap_or_default()[..]);
    
    println!("Hybrid function end successfully!");
    
    Ok(())
}