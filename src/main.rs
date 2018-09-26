extern crate directories;
extern crate env_logger;
extern crate futures;
extern crate gpsoauth;
extern crate hyper;
extern crate hyper_rustls;
extern crate rustls;
extern crate toml;
extern crate webpki_roots;

use directories::ProjectDirs;
use futures::future::{err, ok};
use futures::prelude::*;
use hyper::client::HttpConnector;
use hyper::service::service_fn;
use hyper::{Client, Server};
use hyper_rustls::HttpsConnector;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
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
        .open(&conf_path)
    {
        Ok(mut conf) => {
            conf.metadata().unwrap().permissions().set_mode(0o600);
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
        .open(&new_path)
        .unwrap();
    new_file.metadata().unwrap().permissions().set_mode(0o600);
    new_file.write_all(token.as_bytes()).unwrap();
    std::fs::rename(&new_path, token_path).unwrap();
}

fn master_auth_async(
    client: &Client<HttpsConnector<HttpConnector>>,
    username: &str,
    password: &str,
    device_id: &str,
) -> impl Future<Item = String, Error = ()> {
    client
        .request(gpsoauth::master_login_request(
            username, password, device_id,
        )).and_then(move |res| {
            res.into_body().fold(None, |acc, chunk| {
                ok::<_, hyper::Error>(chunk.lines().fold(acc, |acc, line| {
                    let line = line.unwrap();
                    if line.starts_with("Token=") {
                        Some(line[6..].to_owned())
                    } else {
                        acc
                    }
                }))
            })
        }).map_err(|e| eprintln!("Login error {}", e))
        .then(|r| {
            if let Ok(Some(x)) = r {
                ok(x)
            } else if let Err(y) = r {
                err(y)
            } else {
                err(eprintln!("Login error (no token)"))
            }
        })
}

fn oauth_async(
    client: &Client<HttpsConnector<HttpConnector>>,
    username: &str,
    master_token: &str,
    device_id: &str,
) -> impl Future<Item = String, Error = ()> {
    client
        .request(gpsoauth::oauth_request(
            username,
            master_token,
            device_id,
            "sj",
            "com.google.android.music",
            "38918a453d07199354f8b19af05ec6562ced5788",
        )).and_then(move |res| {
            res.into_body().fold(None, |acc, chunk| {
                ok::<_, hyper::Error>(chunk.lines().fold(acc, |acc, line| {
                    let line = line.unwrap();
                    if line.starts_with("Auth=") {
                        Some(line[5..].to_owned())
                    } else {
                        acc
                    }
                }))
            })
        }).map_err(|e| eprintln!("Login error {}", e))
        .then(|r| {
            if let Ok(Some(x)) = r {
                ok(x)
            } else if let Err(y) = r {
                err(y)
            } else {
                err(eprintln!("Login error (no token)"))
            }
        })
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
    let client = Client::builder().build::<_, hyper::Body>(https);

    let username = conf["username"].as_str().unwrap().to_owned();
    let password = conf["password"].as_str().unwrap().to_owned();
    let device_id = conf["device-id"].as_str().unwrap().to_owned();

    // Clone the client so that the compiler trusts us not to
    // reuse the same client across multiple closures
    let client1 = client.clone();

    let main_future = master_auth_async(
        &client,
        username.as_str(),
        password.as_str(),
        device_id.as_str(),
    ).and_then(move |master_token| {
        println!("Master token is {}", master_token);
        write_token(&master_token_path, &master_token);
        oauth_async(
            &client1,
            username.as_str(),
            &master_token,
            device_id.as_str(),
        )
    }).and_then(move |oauth_token| {
        println!("OAuth token is {}", oauth_token);
        write_token(&oauth_token_path, &oauth_token);
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
