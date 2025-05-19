# axial-rs

Axial - All in One web framework for Rust.

**All in One - everything you need to develop web servers in one framework**

The framework is inspired by [Ruby on Rails](https://github.com/rails/rails)

## Usage

To specify server routes, the `#[axial_macros::get("/path")]` macro (or another type) is used.
Next is the function that describes this route:

```rust
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
```

`async` and returning `impl Responder` are **mandatory!**

The code is quite similar to [actix_web](https://github.com/actix/actix-web), but the goal of my framework is to put everything necessary in one place, providing a convenient API.

### Structures

**Response**:

This structure provides access to the response to a request. Methods:

*   **body(String)** - sets the body of the request;
*   **status(u16)** - response status;
*   **header(impl Into<String>, value: impl Into<String>)** - sets the response header;
*   **cookie(impl Into<String>, value: impl Into<String>)** - sets a cookie to the response;
*   **new(u16)** - response constructor. Takes the response status as input.

All functions return the Response structure.

---

**Request**:

This structure provides access to the request. You can get data from a specific request like this:

`async fn greet(req: Request) -> impl Responder`

`req` will give you access to the request fields:

*   **body** - access to the request body. Returns String;
*   **headers** - access to the request headers. Returns Vec<(String, String)>;
*   **method** - access to the method by which the request came. Returns enum Methods;

```rust
pub enum Methods {
    GET,
    POST,
    PUT,
    DELETE,
}
```

*   **path** - access to the request path. Returns String;
*   **path_params** - access to the path fields (those that you specify via {name} in the path of the macro: `#[get("/user/{id}` = `/user/1`). Returns `Arc<HashMap<String, String, RandomState>, Global>`;
*   **query_string** - access to the path parameters (those specified in the request via `?`: `/user?name=somename`. Returns Option<String>

### Starting the server

```rust
HttpServer::new(String::from("127.0.0.1"), 9092).service(get_user_details)
        .service(post_user_details).start()
        .await.map_err(|e| {
            eprintln!("Error on start server: {e}")
        }).unwrap();
```

The server constructor is called via HttpServer::new(host: String, port: u16);

Each route function is specified via the `.service()` function (1 function = 1 `service()` call);

The server is started by the `start()` function - an asynchronous function that can return an error, so it should be handled in the code.

---

## Client

*Access to client functionality can be obtained using feature = "client".*

Example:

```rust
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
```

*   `HttpClient::new()` - client constructor call;
*   `timeout(Option<std::time::Duration>)` - specifies the timeout;
*   `user_agent(Option<String>)` - specifies the user agent for the request. The framework has (at the time of publication) two constants (one for each OS available under one name): USER_AGENT_CHROME and USER_AGENT_FIREFOX.

```rust
#[cfg(target_os = "windows")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
#[cfg(target_os = "linux")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
#[cfg(target_os = "macos")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

#[cfg(target_os = "windows")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0";
#[cfg(target_os = "macos")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:128.0) Gecko/20100101 Firefox/128.0";
#[cfg(target_os = "linux")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (X11; Linux i686; rv:128.0) Gecko/20100101 Firefox/128.0";
```

*   `build()` - will build the client. Returns Result<HttpClient, String>, so you need to handle the error.

You can send requests:

*   `client.get(url: &str)` - get request to the link. The function receives (in addition to the link) `self`, so the example uses `client: HttpClient`;
*   `client.post(url: &str, body: &String)` - post request to the link (with body);
*   `client.put(url: &str, body: &String)` - put request to the link (with body);
*   `client.delete(url: &str)` - delete request to the link.

All functions are asynchronous and return Result<String, String> - the response body.

---

A little about the attribute to the routes:

This `get`, `post`, etc. are procedural macros that translate your asynchronous function into a structure and make an implementation for it, which then goes to `core::routes::router::RouteFactory` and is adapted for the server. The `serivce()` passes exactly the generic type routes::router::RouteFactory.

---

## Installation

Classic:

*   `cargo add axial`
*   `cargo add axial_macros`

If you also need a client:

*   `cargo add axial --features=client`
