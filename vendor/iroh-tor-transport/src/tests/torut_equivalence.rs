//! Temporary equivalence tests: the built-in control client and onion encoding
//! must produce exactly what torut 0.2.1 produced. Removed with torut.

use std::{future::Future, net::SocketAddr, path::PathBuf, pin::Pin};

use iroh::SecretKey;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, duplex};
use torut::{
    control::{AuthenticatedConn, ConnError, UnauthenticatedConn},
    onion::TorPublicKeyV3,
};

use crate::{
    control::{ControlError, TorControl},
    iroh_to_tor_secret_key,
    onion::{ExpandedSecretKey, OnionAddressV3},
};

type Handler = Box<
    dyn Fn(
            torut::control::AsyncEvent<'static>,
        ) -> Pin<Box<dyn Future<Output = Result<(), ConnError>> + Send>>
        + Send
        + Sync,
>;

fn seed(hex: &str) -> [u8; 32] {
    data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .unwrap()
        .try_into()
        .unwrap()
}

/// RFC 8032 section 7.1 TEST 1 and TEST 2 seeds, edge seeds, and random keys.
fn keys() -> Vec<SecretKey> {
    let mut keys = vec![
        SecretKey::from_bytes(&seed(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )),
        SecretKey::from_bytes(&seed(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        )),
        SecretKey::from_bytes(&[0u8; 32]),
        SecretKey::from_bytes(&[0xffu8; 32]),
    ];
    keys.extend((0..64).map(|_| SecretKey::generate()));
    keys
}

/// Fake Tor control port: for each canned reply, read one request line, then
/// send the reply. Returns every byte the client sent.
async fn fake_tor(server: DuplexStream, replies: Vec<String>) -> Vec<u8> {
    let mut reader = BufReader::new(server);
    let mut transcript = Vec::new();
    for reply in replies {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).await.unwrap();
        transcript.extend_from_slice(&line);
        reader.get_mut().write_all(reply.as_bytes()).await.unwrap();
    }
    transcript
}

#[test]
fn expanded_key_and_derived_public_key_match_torut() {
    for key in keys() {
        let torut_key = iroh_to_tor_secret_key(&key);
        let ours = ExpandedSecretKey::from_seed(&key.to_bytes());
        assert_eq!(ours.as_bytes(), &torut_key.as_bytes());
        // torut derives the public key from the expanded key itself
        // (ed25519-dalek 1); iroh derives it from the seed (ed25519-dalek 3).
        assert_eq!(torut_key.public().as_bytes(), key.public().as_bytes());
    }
}

#[test]
fn onion_address_matches_torut() {
    for key in keys() {
        let public = key.public();
        let torut_addr = TorPublicKeyV3::from_bytes(public.as_bytes())
            .unwrap()
            .get_onion_address();
        let ours = OnionAddressV3::from_public_key(public.as_bytes());
        assert_eq!(ours.service_id(), torut_addr.get_address_without_dot_onion());
        assert_eq!(ours.to_string(), torut_addr.to_string());
        let via_secret = iroh_to_tor_secret_key(&key).public().get_onion_address();
        assert_eq!(ours.to_string(), via_secret.to_string());
    }
}

#[tokio::test]
async fn add_onion_wire_bytes_match_torut() {
    let target: SocketAddr = "127.0.0.1:43210".parse().unwrap();
    for key in keys() {
        let reply = || vec!["250-ServiceID=x\r\n250 OK\r\n".to_string()];

        let (client, server) = duplex(64 * 1024);
        let server = tokio::spawn(fake_tor(server, reply()));
        let mut conn: AuthenticatedConn<DuplexStream, Handler> =
            UnauthenticatedConn::new(client).into_authenticated().await;
        conn.add_onion_v3(
            &iroh_to_tor_secret_key(&key),
            false,
            false,
            false,
            None,
            &mut [(9999u16, target)].iter(),
        )
        .await
        .unwrap();
        let torut_bytes = server.await.unwrap();

        let (client, server) = duplex(64 * 1024);
        let server = tokio::spawn(fake_tor(server, reply()));
        let mut ours = TorControl::new(client);
        let service_id = ours
            .add_onion_v3(&ExpandedSecretKey::from_seed(&key.to_bytes()), 9999, target)
            .await
            .unwrap();
        let our_bytes = server.await.unwrap();

        assert_eq!(service_id.as_deref(), Some("x"));
        assert_eq!(
            String::from_utf8(our_bytes).unwrap(),
            String::from_utf8(torut_bytes).unwrap()
        );
    }
}

#[tokio::test]
async fn add_onion_existing_service_code_matches_torut() {
    let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let key = SecretKey::generate();
    let reply = || vec!["552 Onion address collision\r\n".to_string()];

    let (client, server) = duplex(64 * 1024);
    let server_task = tokio::spawn(fake_tor(server, reply()));
    let mut conn: AuthenticatedConn<DuplexStream, Handler> =
        UnauthenticatedConn::new(client).into_authenticated().await;
    let err = conn
        .add_onion_v3(
            &iroh_to_tor_secret_key(&key),
            false,
            false,
            false,
            None,
            &mut [(9999u16, target)].iter(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ConnError::InvalidResponseCode(552)));
    server_task.await.unwrap();

    let (client, server) = duplex(64 * 1024);
    let server_task = tokio::spawn(fake_tor(server, reply()));
    let err = TorControl::new(client)
        .add_onion_v3(&ExpandedSecretKey::from_seed(&key.to_bytes()), 9999, target)
        .await
        .unwrap_err();
    assert!(matches!(err, ControlError::Status { code: 552, .. }), "{err:?}");
    server_task.await.unwrap();
}

fn cookie_file(name: &str) -> (PathBuf, [u8; 32]) {
    let dir = std::env::temp_dir().join(format!(
        "arachne-tor-equivalence-{}-{}",
        std::process::id(),
        name.len()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let mut cookie = [0u8; 32];
    for (i, b) in cookie.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(name.len() as u8);
    }
    std::fs::write(&path, cookie).unwrap();
    (path, cookie)
}

/// Quote a path the way Tor's `esc_for_log` does for the characters used here.
fn quote(path: &std::path::Path) -> String {
    let raw = path.to_str().unwrap();
    let mut out = String::from("\"");
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn protocol_info_reply(auth_line: &str) -> String {
    format!(
        "250-PROTOCOLINFO 1\r\n250-{auth_line}\r\n250-VERSION Tor=\"0.4.8.10\"\r\n250 OK\r\n"
    )
}

async fn torut_handshake(replies: Vec<String>) -> Vec<u8> {
    let (client, server) = duplex(64 * 1024);
    let server = tokio::spawn(fake_tor(server, replies));
    let mut conn = UnauthenticatedConn::new(client);
    let auth = {
        let info = conn.load_protocol_info().await.unwrap();
        info.make_auth_data().unwrap()
    };
    if let Some(auth) = auth {
        conn.authenticate(&auth).await.unwrap();
    }
    server.await.unwrap()
}

async fn our_handshake(replies: Vec<String>) -> Vec<u8> {
    let (client, server) = duplex(64 * 1024);
    let server = tokio::spawn(fake_tor(server, replies));
    let mut conn = TorControl::new(client);
    let info = conn.protocol_info().await.unwrap();
    if let Some(auth) = info.auth_data().await.unwrap() {
        conn.authenticate(&auth).await.unwrap();
    }
    server.await.unwrap()
}

#[tokio::test]
async fn protocol_info_and_authenticate_wire_bytes_match_torut() {
    let (plain, _) = cookie_file("control_auth_cookie");
    let (odd, _) = cookie_file("odd \"name\" with \\ and space");
    let ok = "250 OK\r\n".to_string();
    let cases: Vec<Vec<String>> = vec![
        vec![protocol_info_reply("AUTH METHODS=NULL"), ok.clone()],
        vec![
            protocol_info_reply(&format!(
                "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE={}",
                quote(&plain)
            )),
            ok.clone(),
        ],
        vec![
            protocol_info_reply(&format!("AUTH METHODS=SAFECOOKIE COOKIEFILE={}", quote(&plain))),
            ok.clone(),
        ],
        vec![
            protocol_info_reply(&format!("AUTH METHODS=COOKIE COOKIEFILE={}", quote(&odd))),
            ok.clone(),
        ],
        vec![
            protocol_info_reply(&format!(
                "AUTH METHODS=NULL,COOKIE COOKIEFILE={}",
                quote(&plain)
            )),
            ok.clone(),
        ],
        // No usable method: neither client sends AUTHENTICATE.
        vec![protocol_info_reply("AUTH METHODS=HASHEDPASSWORD")],
    ];
    for replies in cases {
        let torut = torut_handshake(replies.clone()).await;
        let ours = our_handshake(replies.clone()).await;
        assert_eq!(
            String::from_utf8(ours).unwrap(),
            String::from_utf8(torut).unwrap(),
            "{replies:?}"
        );
    }
}

/// Prints the pinned literals used by the torut-free tests.
#[tokio::test]
async fn print_pinned_vectors() {
    let target: SocketAddr = "127.0.0.1:43210".parse().unwrap();
    for key in keys().into_iter().take(2) {
        let torut_key = iroh_to_tor_secret_key(&key);
        let onion = torut_key.public().get_onion_address();
        let (client, server) = duplex(64 * 1024);
        let server = tokio::spawn(fake_tor(server, vec!["250 OK\r\n".to_string()]));
        let mut conn: AuthenticatedConn<DuplexStream, Handler> =
            UnauthenticatedConn::new(client).into_authenticated().await;
        conn.add_onion_v3(&torut_key, false, false, false, None, &mut [(9999u16, target)].iter())
            .await
            .unwrap();
        let line = String::from_utf8(server.await.unwrap()).unwrap();
        println!(
            "seed={} torut_public={} onion={} add_onion={:?}",
            data_encoding::HEXLOWER.encode(&key.to_bytes()),
            data_encoding::HEXLOWER.encode(torut_key.public().as_bytes()),
            onion,
            line
        );
    }
}
