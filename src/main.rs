use clap::Parser as ClapParser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use std::io::Error as IoError;
use std::path::Path;
use std::sync::Arc;

use async_std::{fs::OpenOptions, io};
use tempfile::TempDir;
use tide::prelude::*;
use tide::{http::mime, Body, Redirect, Request, Response, Server, StatusCode};

use core::str::FromStr;
use handlebars::Handlebars;
use std::collections::BTreeMap;
use tide_handlebars::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, ClapParser)]
struct CreateActorOpts {
    #[clap(short = 'u', long = "username", help = "Username for the new actor")]
    username: String,
    #[clap(short = 'n', long = "name", help = "Name (human-readable)")]
    name: String,
    #[clap(short = 's', long = "summary", help = "Short summary about the actor")]
    summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ClapParser)]
enum LitirOperation {
    #[clap(name = "web-service", about = "Run the web service")]
    WebService,
    #[clap(name = "create-actor", about = "Create a new actor")]
    CreateActor(CreateActorOpts),
}

/// This program does something useful, but its author needs to edit this.
/// Else it will be just hanging around forever
#[derive(Debug, Clone, ClapParser, Serialize, Deserialize)]
#[clap(version = env!("GIT_VERSION"), author = "Andrew Yourtchenko <ayourtch@gmail.com>")]
struct Opts {
    /// Database path
    #[clap(short)]
    db: String,

    /// Override options from this yaml/json file
    #[clap(short, long)]
    options_override: Option<String>,

    /// Operation to do
    #[clap(subcommand)]
    operation: LitirOperation,

    /// A level of verbosity, and can be used multiple times
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,
}

enum DbPool {
    Sqlite(sqlx::sqlite::SqlitePool),
    Pg(sqlx::postgres::PgPool),
}

use sqlx::{FromRow, Row};
#[derive(Debug, FromRow, Clone)]
struct ApActor {
    id: i64,
    username: String,
    pubkey: String,
    privkey: String,
    name: String,
    summary: String,
}

impl ApActor {
    pub fn get_actor_url(&self) -> String {
        format!("https://{}/users/{}", root_fqdn(), self.username)
    }
}

macro_rules! xdb {
    ($db:ident, $pool:ident, $tree: tt) => {
        match &$db {
            DbPool::Sqlite($pool) => $tree,
            DbPool::Pg($pool) => $tree,
        }
    };
}

#[derive(Clone)]
struct AyTestState {
    tempdir: Arc<TempDir>,
    db: Arc<DbPool>,
    registry: Handlebars<'static>,
}

impl AyTestState {
    fn try_new(db: DbPool) -> Result<Self, IoError> {
        Ok(Self {
            tempdir: Arc::new(tempfile::tempdir()?),
            db: Arc::new(db),
            registry: Handlebars::new(),
        })
    }

    fn pool(&self) -> &DbPool {
        &self.db
    }

    fn path(&self) -> &Path {
        self.tempdir.path()
    }
}

#[derive(Deserialize)]
struct RequestQuery {
    url: String,
}

async fn request_url(mut req: Request<AyTestState>) -> tide::Result {
    let RequestQuery { url } = req.query()?; // .unwrap();
    let mut res: surf::Response = surf::get(url).await?;
    let data: String = res.body_string().await?;

    Ok(data.into())
}

#[derive(Deserialize)]
struct WebfingerQuery {
    resource: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebfingerLink {
    rel: String,
    #[serde(rename = "type")]
    typ: String,
    href: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebfingerReply {
    subject: String,
    links: Vec<WebfingerLink>,
}

fn root_fqdn() -> String {
    if let Ok(fqdn) = std::env::var("LITIR_FQDN") {
        format!("{}", &fqdn)
    } else {
        format!("x25.me")
    }
}

async fn db_get_user(db: &DbPool, name: &str) -> Option<ApActor> {
    let users: Vec<ApActor> = xdb!(db, pool, {
        let select_query = sqlx::query_as(
            "SELECT id, username, pubkey, privkey, name, summary FROM actors where username=$1",
        )
        .bind(name);
        select_query.fetch_all(pool).await.unwrap()
    });
    // println!("Got: #{:?}", &users);
    if users.len() == 0 {
        None
    } else {
        Some(users[0].clone())
    }
}

async fn webfinger(mut req: Request<AyTestState>) -> tide::Result {
    let WebfingerQuery { resource } = req.query()?;
    let mut json_reply = "".to_string();
    println!("Webfinger request for {}", &resource);
    if resource.starts_with("acct:") {
        let fqdn = &resource[5..];
        let name = fqdn.split("@").nth(0).unwrap();

        let mut links: Vec<WebfingerLink> = vec![];
        let maybe_actor = db_get_user(req.state().pool(), &name).await;
        if maybe_actor.is_none() {
            return Ok(Response::builder(404)
                .body("")
                .header("cache-control", "max-age=60, public")
                .content_type(mime::HTML)
                .build());
        }

        let mylink = WebfingerLink {
            rel: "self".to_string(),
            typ: "application/activity+json".to_string(),
            href: format!("https://{}/users/{}", root_fqdn(), &name),
        };
        links.push(mylink);
        let rep = WebfingerReply {
            subject: resource,
            links,
        };
        json_reply = serde_json::to_string(&rep).unwrap()
    }

    Ok(json_reply.into())
}
async fn test_sign(mut req: Request<AyTestState>) -> tide::Result {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::{Signer, Verifier};
    use std::fmt::Write;
    println!("Test sign");
    let name = format!("testayourtch");
    let maybe_actor = db_get_user(req.state().pool(), &name).await;
    let actor = maybe_actor.unwrap();

    let private_key_pem = actor.privkey.clone();
    let passphrase = "litir_test";

    let rsa =
        Rsa::private_key_from_pem_passphrase(private_key_pem.as_bytes(), passphrase.as_bytes())
            .unwrap();

    let keypair = PKey::from_rsa(rsa).unwrap();

    let data = b"hello, world!";

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(data).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    let mut out = openssl::base64::encode_block(&signature);

    // let mut out = format!("");
    // writeln!(out, "Result:");
    Ok(out.into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonActivityPublicKey {
    id: String,
    owner: String,
    publicKeyPem: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UserJsonActivity {
    #[serde(rename = "@context")]
    context: Vec<String>, /* not quite right but will work for now */
    id: String,
    #[serde(rename = "type")]
    typ: String,
    preferredUsername: String,
    name: String,
    summary: String,
    inbox: String,
    publicKey: JsonActivityPublicKey,
}

fn get_actor_html(user: &ApActor) -> String {
    use std::fmt::Write;
    let mut out = format!("<html><body>\n");
    writeln!(out, "<h1>{}</h1>", &user.username);
    writeln!(out, "</body></html>");
    out
}

fn get_actor_json(user: &ApActor) -> String {
    let user_url = user.get_actor_url();

    let publicKey = JsonActivityPublicKey {
        id: format!("{}#main-key", &user_url),
        owner: user_url.clone(),
        publicKeyPem: user.pubkey.clone(),
    };

    let context = vec![
        "https://www.w3.org/ns/activitystreams".to_string(),
        "https://w3id.org/security/v1".to_string(),
    ];

    let inbox = format!("{}/inbox", &user_url);

    let actor = UserJsonActivity {
        context,
        typ: "Person".to_string(),
        id: user_url.clone(),
        preferredUsername: user.username.clone(),
        name: user.name.clone(),
        summary: user.summary.clone(),
        inbox,
        publicKey,
    };

    let json_reply = serde_json::to_string(&actor).unwrap();
    json_reply
}

async fn users_handler(mut req: Request<AyTestState>) -> tide::Result {
    use http_types::headers::HeaderValues;
    use http_types::headers::ToHeaderValues;
    let default_accept = format!("*/*").to_header_values().unwrap().collect();
    let accept = req.header("accept").unwrap_or(&default_accept);
    let accept_str = format!("{}", accept[0]);
    let username: String = req.param("username")?.into();
    println!(
        "Actor request for: {} (accept_str: {})",
        &username, &accept_str
    );
    let maybe_actor = db_get_user(req.state().pool(), &username).await;
    if maybe_actor.is_none() {
        return Ok("Error".into());
    }
    let user = maybe_actor.unwrap();

    // FIXME: this is a royal hack :)
    if accept_str.starts_with("application/json")
        || accept_str.starts_with("application/activity+json")
        || accept_str.starts_with("application/ld+json")
    {
        println!("Sending json reply");

        Ok(Response::builder(200)
            .body(get_actor_json(&user))
            .header("content-type", "application/activity+json; charset=utf-8")
            .header("cache-control", "max-age=60, public")
            .build())
    } else {
        println!("Sending html reply");
        Ok(Response::builder(200)
            .body(get_actor_html(&user))
            .header("cache-control", "max-age=60, public")
            .content_type(mime::HTML)
            .build())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AcceptMessage {
    #[serde(rename = "@context")]
    context: String,
    id: String,
    #[serde(rename = "type")]
    typ: String,
    actor: String,
    object: String,
}

async fn verify_req(req: &Request<AyTestState>) -> Result<bool, tide::Error> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::{Signer, Verifier};
    use std::collections::HashMap;

    //
    // let j = req.body_json().await?;
    let username: String = req.param("username")?.into();

    if let Some(sig) = req.header("signature") {
        let sig = sig[0].to_string();
        let mut hm: HashMap<String, String> = Default::default();
        // println!("Found signature: '{}'", &sig);
        for val in sig.split(",") {
            if let Some((key, val)) = val.split_once("=") {
                let key = key.to_string();
                let val = if val.starts_with("\"") && val.ends_with("\"") {
                    val[1..val.len() - 1].to_string()
                } else {
                    val.to_string()
                };
                hm.insert(key, val);
            }
        }
        if let Some(url) = hm.get("keyId") {
            let mut res: surf::Response = surf::get(url)
                .header("accept", "application/activity+json")
                .await?;
            let data: String = res.body_string().await?;
            //  println!("Data: {:#?}", &data);
            let actor: serde_json::Value = serde_json::from_str(&data)?;
            let actor_key = &actor["publicKey"]["publicKeyPem"];
            // println!("Actor pub key: {}", &actor_key);

            let signature = openssl::base64::decode_block(&hm["signature"]).unwrap();

            let comparison_string = hm["headers"]
                .split(" ")
                .map(|x| {
                    if x == "(request-target)" {
                        format!("(request-target): post /users/{}/inbox", &username)
                    } else {
                        format!("{}: {}", x, req.header(x).unwrap()[0])
                    }
                })
                .collect::<Vec<String>>()
                .join("\n");
            // println!("comp string: {:#?}", &comparison_string);
            let key_text = actor_key.as_str().unwrap();
            // println!("Key text: '{}'", &key_text);
            let rsa = Rsa::public_key_from_pem(key_text.as_bytes()).unwrap();
            let keypair = PKey::from_rsa(rsa).unwrap();
            let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
            verifier.update(comparison_string.as_bytes()).unwrap();
            return Ok(verifier.verify(&signature).unwrap());
        }
        //    println!("Hash Map: {:#?}", &hm);
    }
    println!("fallthrough in verify_req");
    Ok(false)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AcceptMsg {
    #[serde(rename = "@context")]
    context: String,
    id: String,
    #[serde(rename = "type")]
    typ: String,
    actor: String,
    object: serde_json::Value,
}

fn digest_str(msg_text: &str) -> String {
    use openssl::hash::MessageDigest;
    let hash = openssl::hash::hash(MessageDigest::sha256(), &msg_text.as_bytes()).unwrap();
    let hash_out = openssl::base64::encode_block(&hash);
    hash_out
}

fn error_response(msg: &str) -> tide::Response {
    Response::builder(401)
        .body(msg.to_string())
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "max-age=60, public")
        .build()
}

async fn sign_and_send(
    pool: &DbPool,
    msg_text: &str,
    from_actor: &str,
    to_actor: &str,
) -> tide::Result {
    use chrono::{DateTime, Utc};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::{Signer, Verifier};
    use std::fmt::Write;

    // FIXME: make a better way
    let object_name = from_actor
        .replace(&format!("https://{}/users/", root_fqdn()), "")
        .to_string();
    assert!(!object_name.starts_with("https://"));
    // FIXME: get their inbox
    let inbox = format!("{}/inbox", &to_actor);
    let inbox_url = surf::Url::parse(&inbox)?;
    let inboxFragment = inbox_url.path();
    let inboxHost = inbox_url.host().unwrap().to_string();

    let maybe_actor = db_get_user(pool, &object_name).await;
    let actor_obj = maybe_actor.unwrap();

    let private_key_pem = actor_obj.privkey.clone();
    let passphrase = "litir_test";

    let rsa =
        Rsa::private_key_from_pem_passphrase(private_key_pem.as_bytes(), passphrase.as_bytes());

    if rsa.is_err() {
        return Ok(error_response(&format!("internal error: {:?}", &rsa)));
    }
    let rsa = rsa.unwrap();

    let hash_out = digest_str(&msg_text);

    let now: DateTime<Utc> = Utc::now();
    // let now_str = format!("{}", now.format("%a, %d %b %Y %T UTC"));
    let now_str = format!("{}", now.format("%a, %-d %b %Y %X GMT"));
    println!("NowStr: {}", &now_str);
    let string_to_sign = format!(
        "(request-target): post {}\nhost: {}\ndate: {}\ndigest: SHA-256={}",
        &inboxFragment, &inboxHost, &now_str, &hash_out
    );

    println!("String to sign: '{}'", &string_to_sign);

    let keypair = PKey::from_rsa(rsa).unwrap();

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(&string_to_sign.as_bytes()).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let sig_out = openssl::base64::encode_block(&signature);

    let sig_header = format!(
        "keyId=\"{}\",headers=\"(request-target) host date digest\",signature=\"{}\"",
        &format!("{}#main-key", from_actor),
        &sig_out
    );

    /* verify */
    {
        let mut res: surf::Response = surf::get(from_actor)
            .header("accept", "application/activity+json")
            .await?;
        let data: String = res.body_string().await?;
        //  println!("Data: {:#?}", &data);
        let actor: serde_json::Value = serde_json::from_str(&data)?;
        let actor_key = &actor["publicKey"]["publicKeyPem"];
        let key_text = actor_key.as_str().unwrap();
        let rsa = Rsa::public_key_from_pem(key_text.as_bytes()).unwrap();
        let keypair = PKey::from_rsa(rsa).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
        verifier.update(string_to_sign.as_bytes()).unwrap();
        println!("Verify result: {:?}", verifier.verify(&signature).unwrap());
    }
    /* end verify */

    let mut res: surf::Response = surf::post(inbox)
        .header("host", inboxHost)
        .header("date", now_str)
        .header("digest", format!("SHA-256={}", hash_out))
        .header("signature", sig_header)
        .header("accept", "application/activity+json")
        .body(msg_text)
        .await?;
    let data: String = res.body_string().await?;
    println!("Result of reply: {:#?}, code: {}", &data, &res.status());
    Ok(Response::builder(202)
        .body("")
        .header("cache-control", "max-age=60, public")
        .build())
}

async fn inbox_handler(mut req: Request<AyTestState>) -> tide::Result {
    use chrono::{DateTime, Utc};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::{Signer, Verifier};
    use std::fmt::Write;

    use uuid::Uuid;
    let data: String = req.body_string().await.unwrap();
    let hash_out = digest_str(&data);
    if let Some(digest_hdr) = req.header("digest") {
        let digest_str = digest_hdr[0].to_string();
        if digest_str == format!("SHA-256={}", &hash_out) {
            println!("Hash verification ok!");
        } else {
            return Ok(error_response("digest verification failed!"));
        }
    } else {
        return Ok(error_response("digest header missing!"));
    }

    let v: serde_json::Value = serde_json::from_str(&data)?;
    println!("J: {}", &v);

    let result = verify_req(&req).await?;

    println!("Verify result: {}", &result);
    if result {
        if v["type"].as_str().unwrap() == "Follow" {
            if let Some(s) = v["object"].as_str() {
                println!("Follow request to follow {}", &s);

                let accept = AcceptMsg {
                    context: "https://www.w3.org/ns/activitystreams".to_string(),
                    id: format!("https://{}/{}", root_fqdn(), Uuid::new_v4()),
                    typ: format!("Accept"),
                    actor: s.to_string(),
                    object: v.clone(),
                };

                let actor = v["actor"].as_str().unwrap().to_string();
                let msg_text = serde_json::to_string(&accept).unwrap();
                sign_and_send(req.state().pool(), &msg_text, &s, &actor).await
            } else {
                Ok(error_response("Follow should be to a string object"))
            }
        } else if v["type"].as_str().unwrap() == "Undo" {
            if let Some(s) = v["object"]["object"].as_str() {
                println!("Undo follow: {:#?}", &v);
                let accept = AcceptMsg {
                    context: "https://www.w3.org/ns/activitystreams".to_string(),
                    id: format!("https://{}/{}", root_fqdn(), Uuid::new_v4()),
                    typ: format!("Accept"),
                    actor: s.to_string(),
                    object: v.clone(),
                };
                let v = &v["object"];

                let actor = v["actor"].as_str().unwrap().to_string();
                let msg_text = serde_json::to_string(&accept).unwrap();
                sign_and_send(req.state().pool(), &msg_text, &s, &actor).await
            } else {
                Ok(error_response("could not get the object"))
            }
        } else {
            Ok(error_response("Unknown request"))
        }
    } else {
        Ok(Response::builder(404)
            .body("")
            .header("cache-control", "max-age=60, public")
            .build())
    }
}

async fn create_actor(db: &DbPool, cao: &CreateActorOpts) -> i64 {
    use openssl::rsa::{Padding, Rsa};
    use openssl::symm::Cipher;
    println!("Generate user");

    let passphrase = "litir_test";

    let rsa = Rsa::generate(4096).unwrap();
    let private_key: Vec<u8> = rsa
        .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes())
        .unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    let privkey = String::from_utf8(private_key).unwrap();
    let pubkey = String::from_utf8(public_key).unwrap();
    println!("Private key: {}", &privkey);
    println!("Public key: {}", &pubkey);

    {
        let newid = xdb!(db, pool, {
            let row: (i64,) = sqlx::query_as(
                "insert into actors (username, pubkey, privkey, name, summary) values ($1, $2, $3, $4, $5) returning id",
            )
            .bind(cao.username.clone())
            .bind(pubkey)
            .bind(privkey)
            .bind(cao.name.clone())
            .bind(cao.summary.clone())
            .fetch_one(pool)
            .await
            .unwrap();
            row.0
        });

        println!("New id: {:?}", newid);
        newid
    }
}

use std::error;
use std::fmt;

#[derive(Debug)]
struct MyError {
    message: String,
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MyError: {}", self.message)
    }
}

impl error::Error for MyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

async fn get_db_pool(opts: &Opts) -> Result<DbPool, MyError> {
    use sqlx::Row;
    let db = if opts.db.starts_with("sqlite://") {
        let p = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&opts.db)
            .await
            .unwrap();
        DbPool::Sqlite(p)
    } else if opts.db.starts_with("postgresql://") {
        let p = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&opts.db)
            .await
            .unwrap();
        DbPool::Pg(p)
    } else {
        return Err(MyError {
            message: format!(
                "Need a database URL starting either from sqlite:// or from postgresql://"
            ),
        });
    };
    println!("Connected to a db");

    match &db {
        DbPool::Sqlite(pool) => {
            sqlx::query(
                r#"
CREATE TABLE IF NOT EXISTS actors (
  id integer primary key autoincrement,
  username text unique not null,
  pubkey text,
  privkey text,
  name text,
  summary text
);"#,
            )
            .execute(pool)
            .await
            .unwrap();
        }
        DbPool::Pg(pool) => {
            sqlx::query(
                r#"
CREATE TABLE IF NOT EXISTS actors (
  id bigserial,
  username text unique not null,
  pubkey text,
  privkey text,
  name text,
  summary text
);"#,
            )
            .execute(pool)
            .await
            .unwrap();
        }
    };
    // make_user(&db, "testuser").await;
    Ok(db)
}

async fn create_actor_main(opts: &Opts, cao: &CreateActorOpts) -> tide::Result<()> {
    let db = get_db_pool(opts).await?;
    let res = create_actor(&db, cao).await;
    println!("New actor id: {}", res);
    xdb!(db, pool, {
        pool.close().await;
    });

    Ok(())
}

async fn webservice_main(opts: &Opts) -> tide::Result<()> {
    let db = get_db_pool(opts).await?;

    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut state = AyTestState::try_new(db)?;
    let mut app = tide::with_state(state);
    // app.at("/request").get(request_url);
    app.at("/users/:username").get(users_handler);
    app.at("/users/:username/inbox").post(inbox_handler);
    // app.at("/test-sign").get(test_sign);
    app.at("/.well-known/webfinger").get(webfinger);
    app.listen("127.0.0.1:4000").await?;
    Ok(())
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let opts: Opts = Opts::parse();

    // allow to load the options, so far there is no good built-in way
    let opts = if let Some(fname) = &opts.options_override {
        if let Ok(data) = std::fs::read_to_string(&fname) {
            let res = serde_json::from_str(&data);
            if res.is_ok() {
                res.unwrap()
            } else {
                serde_yaml::from_str(&data).unwrap()
            }
        } else {
            opts
        }
    } else {
        opts
    };

    if opts.verbose > 4 {
        let data = serde_json::to_string_pretty(&opts).unwrap();
        println!("{}", data);
        println!("===========");
        let data = serde_yaml::to_string(&opts).unwrap();
        println!("{}", data);
    }

    println!("Hello, here is your options: {:#?}", &opts);
    println!("Your FQDN is: {}", root_fqdn());

    match opts.operation {
        LitirOperation::WebService => webservice_main(&opts).await,
        LitirOperation::CreateActor(ref cao) => create_actor_main(&opts, &cao).await,
    }
}
