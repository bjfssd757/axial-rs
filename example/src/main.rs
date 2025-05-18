use axial_macros::{get, post};
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
async fn get_user_details(req: Request) -> impl Responder {
    let user_id_str = req.path_params.get("id").cloned().unwrap_or_default();

    let version_str = req.query_param("version");

    let mut response_body = format!("User ID: {}", user_id_str);
    if let Some(v) = version_str {
        response_body.push_str(&format!(", Version (from query): {}", v));
    } else {
        response_body.push_str(", Version (from query): not specified");
    }

    Response::new(200).body(response_body)
}

#[post("/user/{id}")]
async fn post_user_details(req: Request) -> impl Responder {
    let user_id_str = req.path_params.get("id").cloned().unwrap_or_default();
    let version_str = req.query_param("version");
    let body = req.body.clone();

    let mut response_body = format!("User ID: {}", user_id_str);
    if let Some(v) = version_str {
        response_body.push_str(&format!(", Version (from query): {}\nBody: {body}", v));
    } else {
        response_body.push_str(", Version (from query): not specified");
    }

    Response::new(201).body(response_body).header("Content-Type", "application/json")
}

#[tokio::main]
async fn main() {
    let response = client().await;

    println!("Response from client: {}", response);

    HttpServer::new(String::from("127.0.0.1"), 9092).service(get_user_details)
        .service(post_user_details).start()
        .await.map_err(|e| {
            eprintln!("Error on start server: {e}")
        }).unwrap();
}