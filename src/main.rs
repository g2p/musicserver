extern crate directories;
extern crate env_logger;
extern crate futures;
extern crate gpsoauth;
extern crate hyper;
extern crate hyper_rustls;
extern crate rustls;
extern crate toml_edit;
extern crate webpki_roots;

use directories::ProjectDirs;
use futures::future::{err, ok, Either};
use hyper::client::HttpConnector;
use hyper::rt::Future;
use hyper::rt::Stream;
use hyper::service::service_fn;
use hyper::{Client, Server};
use hyper_rustls::HttpsConnector;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;

fn open_conf(dirs: &ProjectDirs) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(dirs.config_dir()).unwrap();
    let mut conf_path = std::path::PathBuf::from(dirs.config_dir());
    conf_path.push("config.toml");
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

fn main() {
    env_logger::init();
    let dirs = ProjectDirs::from("com.github", "G2P", "Music Server").unwrap();
    let mut conf = open_conf(&dirs).unwrap();
    let mut conf_buf = String::new();
    conf.read_to_string(&mut conf_buf).unwrap();
    let conf = conf_buf.parse::<toml_edit::Document>().unwrap();
    let conf = &conf["musicserver"];
    let username = conf["username"].as_str().unwrap();
    let password = conf["password"].as_str().unwrap();
    let device_id = conf["device-id"].as_str().unwrap();

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

    let login_req = client
        .request(gpsoauth::master_login_request(
            username, password, device_id,
        ));

    let main_future = login_req
        .map_err(|e| eprintln!("Login error: {}", e))
        .and_then(move |res| {
            res.into_body()
                .fold(None, |acc, chunk| {
                    ok::<_, hyper::Error>(chunk.lines().fold(acc, |acc, line| {
                        let line = line.unwrap();
                        if line.starts_with("Token=") {
                            Some(line[6..].to_owned())
                        } else {
                            acc
                        }
                    }))
                }).map_err(|e| panic!("Error: {:?}", e))
        }).and_then(move |token_opt| {
            if let Some(token) = token_opt {
                println!("Token is {}", token);
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

                Either::A(server)
            } else {
                Either::B(err(eprintln!("Failed to log in")))
            }
        });

    println!("Starting up");
    hyper::rt::run(main_future);
}
