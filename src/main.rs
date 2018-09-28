extern crate directories;
extern crate env_logger;
extern crate futures;
extern crate gpsoauth;
extern crate hyper;
extern crate hyper_rustls;
extern crate rustls;
extern crate serde_json;
extern crate toml;
extern crate webpki_roots;

use directories::ProjectDirs;
use futures::prelude::*;
use gpsoauth::AuthorizedRequestBuilder;
use hyper::client::HttpConnector;
use hyper::service::service_fn;
use hyper::Server;
use hyper_rustls::HttpsConnector;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

const CONF_FILENAME: &'static str = "config.toml";
const CONF_ROOT: &'static str = "musicserver";
const MASTER_TOKEN_FILENAME: &'static str = "master.token";
const OAUTH_TOKEN_FILENAME: &'static str = "oauth.token";

fn open_conf(dirs: &ProjectDirs) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(dirs.data_dir()).unwrap();
    std::fs::create_dir_all(dirs.config_dir()).unwrap();
    let mut conf_path = std::path::PathBuf::from(dirs.config_dir());
    conf_path.push(CONF_FILENAME);
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&conf_path)
    {
        Ok(mut conf) => {
            let conf_example = include_str!("config-example.toml");
            conf.write(conf_example.as_bytes()).unwrap();
            conf.seek(SeekFrom::Start(0)).unwrap();
            Ok(conf)
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                std::fs::OpenOptions::new().read(true).open(&conf_path)
            } else {
                Err(e)
            }
        }
    }
}

fn write_token(token_path: &PathBuf, token: &str) {
    let mut new_path = token_path.to_owned();
    let mut new_fn = token_path.file_name().unwrap().to_owned();
    new_fn.push(".new");
    new_path.set_file_name(new_fn);
    let mut new_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&new_path)
        .unwrap();
    new_file.write_all(token.as_bytes()).unwrap();
    std::fs::rename(&new_path, token_path).unwrap();
}

fn main() {
    env_logger::init();
    let dirs = ProjectDirs::from("com.github", "G2P", "Music Server").unwrap();
    let (conf0, conf);
    {
        let mut conf_file = open_conf(&dirs).unwrap();
        let mut conf_buf = String::new();
        conf_file.read_to_string(&mut conf_buf).unwrap();
        conf0 = conf_buf.parse::<toml::Value>().unwrap();
        conf = &conf0[CONF_ROOT];
    }

    let mut master_token_path = std::path::PathBuf::from(dirs.data_dir());
    master_token_path.push(MASTER_TOKEN_FILENAME);
    let mut oauth_token_path = std::path::PathBuf::from(dirs.data_dir());
    oauth_token_path.push(OAUTH_TOKEN_FILENAME);

    // https://seanmonstar.com/post/174480374517/hyper-v012
    let addr = ([0, 0, 0, 0], 3000).into();

    // 4 is the number of blocking DNS threads
    let mut http = HttpConnector::new(4);
    http.enforce_http(false);
    let mut tls_config = rustls::ClientConfig::new();
    tls_config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());
    tls_config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let https = HttpsConnector::from((http, tls_config));
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);

    let username = conf["username"].as_str().unwrap().to_owned();
    let password = conf["password"].as_str().unwrap().to_owned();
    let device_id = conf["device-id"].as_str().unwrap().to_owned();

    // Clone the client so that the compiler trusts us not to
    // reuse the same client across multiple closures
    let client1 = client.clone();
    let client2 = client.clone();

    let main_future = gpsoauth::master_auth_async(
        &client,
        username.as_str(),
        password.as_str(),
        device_id.as_str(),
    ).and_then(move |master_token| {
        println!("Master token is {}", master_token);
        write_token(&master_token_path, &master_token);
        gpsoauth::oauth_async(
            &client1,
            username.as_str(),
            &master_token,
            device_id.as_str(),
            "sj",
            "com.google.android.music",
            "38918a453d07199354f8b19af05ec6562ced5788",
        )
    }).and_then(move |oauth_token| {
        println!("OAuth token is {}", oauth_token);
        write_token(&oauth_token_path, &oauth_token);
        client2.request(hyper::Request::get("https://mclients.googleapis.com/sj/v2.5/devicemanagementinfo?alt=json&hl=en_US&dv=0&tier=fr").authorization_header(&oauth_token).body(hyper::Body::from("")).unwrap())
            .map_err(|e| eprintln!("API error: {}", e))
    }).and_then(|resp| {
        resp.into_body().concat2()
            .map_err(|e| eprintln!("API error (body chunks): {}", e))
    }).and_then(move |body| {
        //println!("Devices: {:#?}", serde_json::from_slice::<serde_json::Value>(&body));
        println!("{}", "Devices: ".to_owned() + std::str::from_utf8(&body).unwrap());
        println!("Listening on {}", addr);
        let proxy_svc = move || {
            let client = client.clone();
            service_fn(move |req| {
                println!("Proxying {}", req.uri().path());
                client.get("http://google.fr/".parse().unwrap())
            })
        };

        let server = Server::bind(&addr)
            .serve(proxy_svc)
            .map_err(|e| eprintln!("Server error: {}", e));

        server
    });

    println!("Starting up");
    hyper::rt::run(main_future);
}
