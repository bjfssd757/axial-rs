# axial-rs

Axial - All in One веб фреймворк для Rust.

> [!NOTE]
> All in One - всё самое нужное для разработки веб серверов в одном фреймворке

Фреймворк вдохновлён [Ruby on Rails](https://github.com/rails/rails)

## Использование

Для указания маршрутов сервера используется макрос `#[axial_macros::get("/path")]` (либо другой тип)
Далее функция, которая описывает этот маршрут:
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

`async`  и возврат `impl Responder` - **обязательно!**

Код довольно похож на [actix_web](https://github.com/actix/actix-web), но цель моего фреймворка - поместить всё самое необходимое в одно место, предоставив удобный API.

### Структуры

**Response**:

Данная структура предоставляет доступ к ответу на запрос. Методы:

* **body(String)** - установка тела запроса;

* **status(u16)** - статус ответа;

* **header(impl Into<String>, value: impl Into<String>)** - установка заголовка ответа;

* **cookie(impl Into<String>, value: impl Into<String>)** - установка куки к ответу;

* **new(u16)** - конструктор ответа. На вход получает статус ответа.

все функции возвращают структуру Response.

---

**Request**:

Данная структура предоставляет доступ к запросу. Получить данные с конкретного запроса можно так:

`async fn greet(req: Request) -> impl Responder`

`req` даст вам доступ к полям запроса:

* **body** - доступ к телу запроса. Вернёт String;

* **headers** - доступ к заголовкам запроса. Вернёт Vec<(String, String)>;

* **method** - доступ к методу, по которому пришёл запрос. Вернёт enum Methods;

`pub enum Methods {
    GET,
    POST,
    PUT,
    DELETE,
}`

* **path** - доступ к пути запроса. Вернёт String;

* **path_params** - доступ к полям пути (те, что вы указзываете через {name} в пути у макроса: `#[get("/user/{id}` = `/user/1`). `Вернёт Arc<HashMap<String, String, RandomState>, Global>`;

* **query_string** - доступ к параметрам пути (те, что указываются в запросе через `?`: `/user?name=somename`. Вернёт Option<String>

### Запуск сервера

```rust
HttpServer::new(String::from("127.0.0.1"), 9092).service(get_user_details)
        .service(post_user_details).start()
        .await.map_err(|e| {
            eprintln!("Error on start server: {e}")
        }).unwrap();
```

Конструктор сервера вызывается через HttpServer::new(host: String, port: u16);

Каждая функция-роут указываются через функцию `.service()` (1 функция = 1 вызов `service()`);

Сервер запускатеся функцией `start()` - асинхронная функция, может вернуть ошибку, поэтому её следует обработать в коде.

---

## Клиент

*Доступ к функциональности клиента можно получить, используя feature = "client".*

Пример:

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

* `HttpClient::new()` - вызов конструктора клиента;

* `timeout(Option<std::time::Duration>)` - указывает таймаут;

* `user_agent(Option<String>)` - указывает юзер агента для запроса. У фреймворка есть (на момент публикации) две константы (под разые ОС доступны по одному имени): USER_AGENT_CHROME и USER_AGENT_FIREFOX.

```rust
#[cfg(target_os = "windows")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
#[cfg(target_os = "linux")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
#[cfg(target_os = "macos")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

#[cfg(target_os = "windows")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0";
#[cfg(target_os = "macos")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:128.0) Gecko/20100101 Firefox/128.0";
#[cfg(target_os = "linux")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (X11; Linux i686; rv:128.0) Gecko/20100101 Firefox/128.0";
```

* `build()` - соберёт клиента. Возвращает Result<HttpClient, String>, поэтому надо обработать ошибку.

Вы можете отправлять запросы:

* `client.get(url: &str)` - get запрос на ссылку. Функция получает (кроме ссылки) `self`, поэтому в примере стоит `client: HttpClient`;

* `client.post(url: &str, body: &String)` - post запрос на ссылку (с телом);

* `client.put(url: &str, body: &String)` - put запрос на ссылку (с телом);

* `client.delete(url: &str)` - delete запрос на ссылку.

Все функции асинхронные и возвращают Result<String, String>- тело ответа.

---

Немного по поводу атрибута к роутам:

Этот `get`, `post` и тд - процедурный макрос, который переводит вашу асинхронную функцию в структуру и сделает для неё реализацию, которая далее пойдёт в `core::routes::router::RouteFactory` и адаптирована для сервера. В `serivce()` передаётся как раз generic тип routes::router::RouteFactory.

---

## Установка

Классика:

* `cargo add axial`
* `cargo add axial_macros`

Если вам нужен также клиент:

* `cargo add axial --features=client`
