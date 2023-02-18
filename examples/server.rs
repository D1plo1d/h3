use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http::{HeaderValue, Method, Request, StatusCode};
use rustls::{Certificate, PrivateKey};
use structopt::StructOpt;
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{debug, error, info, trace_span};

use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time};

use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use h3_quinn::quinn;

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK."
    )]
    pub root: Option<PathBuf>,

    #[structopt(
        short,
        long,
        default_value = "[::1]:4430",
        help = "What address:port to listen for new connections"
    )]
    pub listen: SocketAddr,

    #[structopt(flatten)]
    pub certs: Certs,
}

#[derive(StructOpt, Debug)]
pub struct Certs {
    #[structopt(
        long,
        short,
        default_value = "examples/server.cert",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    pub cert: PathBuf,

    #[structopt(
        long,
        short,
        default_value = "examples/server.key",
        help = "Private key for the certificate."
    )]
    pub key: PathBuf,
}

static ALPN: &[u8] = b"h3";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    // process cli arguments

    let opt = Opt::from_args();

    let root = if let Some(root) = opt.root {
        if !root.is_dir() {
            return Err(format!("{}: is not a readable directory", root.display()).into());
        } else {
            info!("serving {}", root.display());
            Arc::new(Some(root))
        }
    } else {
        Arc::new(None)
    };

    // let crypto = load_crypto(opt.certs).await?;
    // let server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // debug!("Server config {:?}", server_config);
    // dbg!(&server_config);
    // let (endpoint, mut incoming) = h3_quinn::quinn::Endpoint::server(server_config, opt.listen)?;

    // create quinn server endpoint and bind UDP socket

    // let Certs { cert, key } = opt.certs;

    // both cert and key must be DER-encoded
    // let cert = Certificate(std::fs::read(cert)?);
    // let key = PrivateKey(std::fs::read(key)?);
    let (cert, key) = build_certs();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![ALPN.into()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
    let (endpoint, mut incoming) = quinn::Endpoint::server(server_config, opt.listen)?;

    info!("listening on {}", opt.listen);

    // handle incoming connections and requests

    while let Some(new_conn) = incoming.next().await {
        trace_span!("New connection being attempted");
        info!("New connection");

        let root = root.clone();

        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new connection established");

                    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();
                    info!("h3 now established");
                    loop {
                        match h3_conn.accept().await {
                            Ok(Some((req, stream))) => {
                                info!("new request: {:#?}", req);

                                let root = root.clone();

                                tokio::spawn(async {
                                    if let Err(e) = handle_request(req, stream, root).await {
                                        error!("handling request failed: {}", e);
                                    }
                                });
                            }

                            // indicating no more streams to be received
                            Ok(None) => {
                                info!("Connection closed");
                                break;
                            }

                            Err(err) => {
                                error!("error on accept {}", err);
                                match err.get_error_level() {
                                    ErrorLevel::ConnectionError => break,
                                    ErrorLevel::StreamError => continue,
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("accepting connection failed: {:?}", err);
                }
            }
        });
    }

    // shut down gracefully
    // wait for connections to be closed before exiting
    endpoint.wait_idle().await;

    Ok(())
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<Option<PathBuf>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let (status, to_serve) = if dbg!(req.method() == Method::CONNECT) {
        let origin = req.headers().get("origin");

        if dbg!(req.uri().path()) != "/wt" {
            (StatusCode::NOT_FOUND, None)
        } else if dbg!(origin) != Some(&"http://localhost:8000".parse()?) {
            debug!("Incorrect Origin: {origin:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, None)
        } else {
            (StatusCode::OK, None)
        }
    } else {
        match serve_root.as_deref() {
            None => (StatusCode::OK, None),
            Some(_) if req.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
            Some(root) => {
                let to_serve = root.join(req.uri().path().strip_prefix('/').unwrap_or(""));
                match File::open(&to_serve).await {
                    Ok(file) => (StatusCode::OK, Some(file)),
                    Err(e) => {
                        error!("failed to open: \"{}\": {}", to_serve.to_string_lossy(), e);
                        (StatusCode::NOT_FOUND, None)
                    }
                }
            }
        }
    };

    let resp = http::Response::builder().status(status).body(()).unwrap();

    match stream.send_response(resp).await {
        Ok(_) => {
            info!("successfully respond to connection");
        }
        Err(err) => {
            error!("unable to send response to connection peer: {:?}", err);
        }
    }

    if let Some(mut file) = to_serve {
        loop {
            let mut buf = BytesMut::with_capacity(4096 * 10);
            if file.read_buf(&mut buf).await? == 0 {
                break;
            }
            stream.send_data(buf.freeze()).await?;
        }
    }

    Ok(stream.finish().await?)
}

// static ALPN: &[u8] = b"h3";

// async fn load_crypto(opt: Certs) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
//     let (cert, key) = match (opt.cert, opt.key) {
//         (None, None) => build_certs(),
//         (Some(cert_path), Some(ref key_path)) => {
//             let mut cert_v = Vec::new();
//             let mut key_v = Vec::new();

//             let mut cert_f = File::open(cert_path).await?;
//             let mut key_f = File::open(key_path).await?;

//             cert_f.read_to_end(&mut cert_v).await?;
//             key_f.read_to_end(&mut key_v).await?;

//             let key_der = rustls_pemfile::pkcs8_private_keys(&mut &*key_v)
//                 .expect("malformed PKCS #8 private key")
//                 .pop()
//                 .expect("No private keys in PEM file");

//             let cert = rustls_pemfile::certs(&mut &*cert_v)
//                 .expect("Invalid PEM-encoding for certificate")
//                 .pop()
//                 .expect("Cert file does not contain any certs");

//             (rustls::Certificate(cert), PrivateKey(key_der))
//         }
//         (_, _) => return Err("cert and key args are mutually dependant".into()),
//     };

//     let mut crypto = rustls::ServerConfig::builder()
//         .with_safe_default_cipher_suites()
//         .with_safe_default_kx_groups()
//         .with_protocol_versions(&[&rustls::version::TLS13])
//         .unwrap()
//         .with_no_client_auth()
//         .with_single_cert(vec![cert], key)
//         .unwrap();
//     crypto.max_early_data_size = u32::MAX;
//     crypto.alpn_protocols = vec![ALPN.into()];

//     Ok(crypto)
// }

pub fn build_certs() -> (Certificate, PrivateKey) {
    // let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]);
    // params.not_before = OffsetDateTime::now_utc();
    // params.not_after = OffsetDateTime::now_utc() + Duration::days(10);
    // params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    // let cert = rcgen::Certificate::from_params(params).unwrap();

    // // let public_der = cert.get_key_pair().public_key_der();
    // let cert_der = cert.serialize_der().unwrap();
    // std::fs::write("./der_test", cert.serialize_private_key_pem()).unwrap();
    // std::fs::write("./der_test.cert", cert.serialize_pem().unwrap()).unwrap();
    // let cert_pem = std::fs::read("./der_test.cert").unwrap();

    let cert_pem = std::fs::File::open("./der_test.cert").unwrap();
    let mut cert_pem = std::io::BufReader::new(cert_pem);
    let priv_key_pem = std::fs::File::open("./der_test").unwrap();
    let mut priv_key_pem = std::io::BufReader::new(priv_key_pem);

    let cert_der = rustls_pemfile::certs(&mut cert_pem).unwrap();
    let cert_der = cert_der.first().unwrap();

    let priv_key_der = rustls_pemfile::pkcs8_private_keys(&mut priv_key_pem).unwrap();
    let priv_key_der = priv_key_der.first().unwrap();

    let hash = ring::digest::digest(&ring::digest::SHA256, &cert_der);

    let fingerprint_hex = hash
        .as_ref()
        .iter()
        .map(|v| format!("{:02X?}", v))
        .collect::<Vec<_>>()
        .join(":");
    println!("Cert identifier: {}", fingerprint_hex);

    let hash = ring::digest::digest(&ring::digest::SHA256, &cert_der);

    let hash = hash
        .as_ref()
        .into_iter()
        .into_iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    println!("Cert identifier 2 electric booagloo: {}", hash);

    // let key = PrivateKey(cert.serialize_private_key_der());
    // let cert = Certificate(cert.serialize_der().unwrap());

    let key = PrivateKey(priv_key_der.clone());
    let cert = Certificate(cert_der.clone());
    (cert, key)
}
