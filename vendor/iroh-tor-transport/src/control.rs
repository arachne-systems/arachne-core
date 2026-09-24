// Added by Arachne Systems (not in iroh-tor-transport 0.1.0); see ARACHNE-PATCH.md.
//! Minimal Tor control-port client.
//!
//! Replaces the parts of `torut::control` that this crate used:
//! `PROTOCOLINFO 1`, `AUTHENTICATE` (null or cookie auth) and
//! `ADD_ONION ED25519-V3`. These commands are byte-for-byte the ones torut
//! 0.2.1 sent. In addition, `SAFECOOKIE` authentication (`AUTHCHALLENGE`) is
//! used when Tor offers it. See Tor's control-spec for the protocol.

use std::{fmt, io, net::SocketAddr, path::PathBuf};

use data_encoding::HEXUPPER;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::onion::ExpandedSecretKey;

/// Upper bound for one reply from Tor (the same bound torut used).
const MAX_REPLY_BYTES: usize = 1024 * 1024;

/// Length of Tor's control authentication cookie.
const COOKIE_LEN: usize = 32;

/// Length of the `SAFECOOKIE` client and server nonces.
const NONCE_LEN: usize = 32;

/// HMAC key for the hash Tor sends in `AUTHCHALLENGE` (control-spec 3.24).
const SAFECOOKIE_SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";

/// HMAC key for the hash the controller sends in `AUTHENTICATE`.
const SAFECOOKIE_CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// Error from the Tor control connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum ControlError {
    /// Reading or writing the control connection failed, or Tor closed it.
    Io(io::Error),
    /// Tor sent a reply that this client does not accept.
    Protocol(&'static str),
    /// Tor replied with a status code other than 250.
    Status {
        /// Tor status code, for example 552 for an existing onion service.
        code: u16,
        /// Text of the last reply line.
        message: String,
    },
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "Tor control connection failed: {err}"),
            Self::Protocol(what) => write!(f, "invalid reply from Tor: {what}"),
            Self::Status { code, message } => {
                write!(f, "Tor returned status {code}: {message}")
            }
        }
    }
}

impl std::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

/// Authentication data for `AUTHENTICATE`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AuthData {
    /// No authentication (Tor `NULL` method).
    Null,
    /// Contents of Tor's cookie file, sent as plain `COOKIE` authentication.
    Cookie([u8; COOKIE_LEN]),
    /// Contents of Tor's cookie file, used for `SAFECOOKIE`
    /// challenge-response authentication (`AUTHCHALLENGE`).
    SafeCookie([u8; COOKIE_LEN]),
}

impl fmt::Debug for AuthData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Cookie(_) => f.write_str("Cookie(****)"),
            Self::SafeCookie(_) => f.write_str("SafeCookie(****)"),
        }
    }
}

/// Parsed `PROTOCOLINFO` reply: the auth methods this client knows about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProtocolInfo {
    pub(crate) null: bool,
    pub(crate) cookie: bool,
    pub(crate) safe_cookie: bool,
    pub(crate) cookie_file: Option<PathBuf>,
}

impl ProtocolInfo {
    /// Pick authentication data: `NULL` first, then the cookie file with
    /// `SAFECOOKIE` if offered, else with plain `COOKIE`. The cookie file
    /// must be exactly 32 bytes. Returns `None` when no method works without
    /// a password.
    pub(crate) async fn auth_data(&self) -> io::Result<Option<AuthData>> {
        if self.null {
            return Ok(Some(AuthData::Null));
        }
        let Some(path) = self.cookie_file.as_ref() else {
            return Ok(None);
        };
        if !(self.safe_cookie || self.cookie) {
            return Ok(None);
        }
        // Read one byte more than a cookie to detect a file that is too long.
        let file = tokio::fs::File::open(path).await?;
        let mut contents = Vec::with_capacity(COOKIE_LEN + 1);
        file.take(COOKIE_LEN as u64 + 1)
            .read_to_end(&mut contents)
            .await?;
        let cookie: [u8; COOKIE_LEN] = contents.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Tor cookie file is not exactly 32 bytes",
            )
        })?;
        Ok(Some(if self.safe_cookie {
            AuthData::SafeCookie(cookie)
        } else {
            AuthData::Cookie(cookie)
        }))
    }
}

/// One reply from Tor: its status code and the text of each line.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn expect_ok(self) -> Result<Vec<String>, ControlError> {
        if self.code == 250 {
            Ok(self.lines)
        } else {
            Err(ControlError::Status {
                code: self.code,
                message: self.lines.last().cloned().unwrap_or_default(),
            })
        }
    }
}

/// Tor control-port connection.
///
/// An onion service added without the `Detach` flag lives as long as this
/// connection, so keep the value alive for as long as the service is needed.
pub(crate) struct TorControl<S> {
    stream: BufReader<S>,
}

impl<S> fmt::Debug for TorControl<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TorControl")
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TorControl<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }

    async fn send(&mut self, command: &str) -> Result<(), ControlError> {
        let stream = self.stream.get_mut();
        stream
            .write_all(command.as_bytes())
            .await
            .map_err(ControlError::Io)?;
        stream.flush().await.map_err(ControlError::Io)
    }

    /// Read one reply. Mid lines (`250-`) and the end line (`250 `) must carry
    /// the same code. Data lines (`250+`) are not used by the commands here
    /// and are rejected.
    async fn read_reply(&mut self) -> Result<Reply, ControlError> {
        let mut remaining = MAX_REPLY_BYTES;
        let mut code = None;
        let mut lines = Vec::new();
        loop {
            let mut line = Vec::new();
            let read = (&mut self.stream)
                .take(remaining as u64)
                .read_until(b'\n', &mut line)
                .await
                .map_err(ControlError::Io)?;
            if line.last() != Some(&b'\n') {
                if read == remaining {
                    return Err(ControlError::Protocol("reply too large"));
                }
                return Err(ControlError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Tor closed the control connection",
                )));
            }
            remaining -= read;
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.len() < 4 || !line[..3].iter().all(u8::is_ascii_digit) {
                return Err(ControlError::Protocol("malformed reply line"));
            }
            let status = line[..3]
                .iter()
                .fold(0u16, |acc, digit| acc * 10 + u16::from(digit - b'0'));
            if *code.get_or_insert(status) != status {
                return Err(ControlError::Protocol("status code changed within a reply"));
            }
            let text = String::from_utf8(line[4..].to_vec())
                .map_err(|_| ControlError::Protocol("reply is not UTF-8"))?;
            match line[3] {
                b' ' => {
                    lines.push(text);
                    return Ok(Reply {
                        code: status,
                        lines,
                    });
                }
                b'-' => lines.push(text),
                b'+' => return Err(ControlError::Protocol("unexpected data reply")),
                _ => return Err(ControlError::Protocol("malformed reply line")),
            }
        }
    }

    /// Send `PROTOCOLINFO 1` and parse the auth methods and cookie file.
    pub(crate) async fn protocol_info(&mut self) -> Result<ProtocolInfo, ControlError> {
        self.send("PROTOCOLINFO 1\r\n").await?;
        let lines = self.read_reply().await?.expect_ok()?;
        parse_protocol_info(&lines)
    }

    /// Send `AUTHENTICATE` with the given data.
    pub(crate) async fn authenticate(&mut self, auth: &AuthData) -> Result<(), ControlError> {
        let command = match auth {
            AuthData::Null => "AUTHENTICATE\r\n".to_string(),
            AuthData::Cookie(cookie) => format!("AUTHENTICATE {}\r\n", HEXUPPER.encode(cookie)),
            AuthData::SafeCookie(cookie) => {
                let mut client_nonce = [0u8; NONCE_LEN];
                getrandom::fill(&mut client_nonce).map_err(|err| {
                    ControlError::Io(io::Error::other(format!(
                        "no random bytes for the SAFECOOKIE nonce: {err}"
                    )))
                })?;
                return self.authenticate_safe_cookie(cookie, &client_nonce).await;
            }
        };
        self.send(&command).await?;
        self.read_reply().await?.expect_ok()?;
        Ok(())
    }

    /// `SAFECOOKIE` authentication (control-spec 3.24) with the given client
    /// nonce: `AUTHCHALLENGE`, check Tor's `SERVERHASH` in constant time,
    /// then `AUTHENTICATE` with the controller hash. If `SERVERHASH` is wrong
    /// (the peer does not know the cookie) this fails without sending
    /// `AUTHENTICATE`.
    async fn authenticate_safe_cookie(
        &mut self,
        cookie: &[u8; COOKIE_LEN],
        client_nonce: &[u8; NONCE_LEN],
    ) -> Result<(), ControlError> {
        self.send(&format!(
            "AUTHCHALLENGE SAFECOOKIE {}\r\n",
            HEXUPPER.encode(client_nonce)
        ))
        .await?;
        let lines = self.read_reply().await?.expect_ok()?;
        let (server_hash, server_nonce) = parse_auth_challenge(&lines)?;
        safe_cookie_mac(SAFECOOKIE_SERVER_KEY, cookie, client_nonce, &server_nonce)
            .verify_slice(&server_hash)
            .map_err(|_| ControlError::Protocol("SAFECOOKIE server hash does not match"))?;
        let client_hash =
            safe_cookie_mac(SAFECOOKIE_CLIENT_KEY, cookie, client_nonce, &server_nonce)
                .finalize()
                .into_bytes();
        self.send(&format!(
            "AUTHENTICATE {}\r\n",
            HEXUPPER.encode(&client_hash)
        ))
        .await?;
        self.read_reply().await?.expect_ok()?;
        Ok(())
    }

    /// Add an ephemeral v3 onion service with the given key that forwards
    /// `onion_port` to `target`. The service is removed when this connection
    /// closes. Returns the `ServiceID` that Tor reported, if any.
    pub(crate) async fn add_onion_v3(
        &mut self,
        key: &ExpandedSecretKey,
        onion_port: u16,
        target: SocketAddr,
    ) -> Result<Option<String>, ControlError> {
        // Same bytes as torut 0.2.1, including the trailing space.
        let command = format!(
            "ADD_ONION ED25519-V3:{} Flags=DiscardPK Port={onion_port},{target} \r\n",
            key.key_blob()
        );
        self.send(&command).await?;
        let lines = self.read_reply().await?.expect_ok()?;
        Ok(lines
            .iter()
            .find_map(|line| line.strip_prefix("ServiceID="))
            .map(str::to_string))
    }
}

/// HMAC-SHA256 over `cookie || client_nonce || server_nonce` with the given
/// `SAFECOOKIE` key (control-spec 3.24).
fn safe_cookie_mac(
    key: &[u8],
    cookie: &[u8; COOKIE_LEN],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac
}

/// Parse the one-line `250` reply to `AUTHCHALLENGE`:
/// `AUTHCHALLENGE SERVERHASH=<64 hex> SERVERNONCE=<64 hex>`.
/// Both fields must be present once; other fields are rejected.
fn parse_auth_challenge(lines: &[String]) -> Result<([u8; 32], [u8; NONCE_LEN]), ControlError> {
    let [line] = lines else {
        return Err(ControlError::Protocol(
            "AUTHCHALLENGE reply is not one line",
        ));
    };
    let fields = line
        .strip_prefix("AUTHCHALLENGE ")
        .ok_or(ControlError::Protocol("not an AUTHCHALLENGE reply"))?;
    let mut server_hash = None;
    let mut server_nonce = None;
    for field in fields.split(' ') {
        let (slot, value) = if let Some(value) = field.strip_prefix("SERVERHASH=") {
            (&mut server_hash, value)
        } else if let Some(value) = field.strip_prefix("SERVERNONCE=") {
            (&mut server_nonce, value)
        } else {
            return Err(ControlError::Protocol(
                "unexpected field in AUTHCHALLENGE reply",
            ));
        };
        if slot.is_some() {
            return Err(ControlError::Protocol(
                "repeated field in AUTHCHALLENGE reply",
            ));
        }
        *slot = Some(decode_hex_32(value)?);
    }
    match (server_hash, server_nonce) {
        (Some(hash), Some(nonce)) => Ok((hash, nonce)),
        _ => Err(ControlError::Protocol(
            "AUTHCHALLENGE reply lacks SERVERHASH or SERVERNONCE",
        )),
    }
}

/// Decode exactly 32 bytes of hex (either case).
fn decode_hex_32(value: &str) -> Result<[u8; 32], ControlError> {
    const ERR: ControlError = ControlError::Protocol("AUTHCHALLENGE value is not 32 hex bytes");
    if value.len() != 64 {
        return Err(ERR);
    }
    HEXUPPER
        .decode(value.to_ascii_uppercase().as_bytes())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ERR)
}

/// Parse the lines of a `250` reply to `PROTOCOLINFO 1`.
fn parse_protocol_info(lines: &[String]) -> Result<ProtocolInfo, ControlError> {
    if lines.first().map(String::as_str) != Some("PROTOCOLINFO 1") {
        return Err(ControlError::Protocol("PROTOCOLINFO version is not 1"));
    }
    if lines.last().map(String::as_str) != Some("OK") {
        return Err(ControlError::Protocol(
            "PROTOCOLINFO reply does not end with OK",
        ));
    }
    let auth = lines
        .iter()
        .find_map(|line| line.strip_prefix("AUTH METHODS="))
        .ok_or(ControlError::Protocol(
            "PROTOCOLINFO reply has no AUTH line",
        ))?;
    let (methods, rest) = auth.split_once(' ').unwrap_or((auth, ""));
    let mut info = ProtocolInfo::default();
    for method in methods.split(',') {
        match method {
            "NULL" => info.null = true,
            "COOKIE" => info.cookie = true,
            "SAFECOOKIE" => info.safe_cookie = true,
            // HASHEDPASSWORD and future methods are not used by this client.
            _ => {}
        }
    }
    let rest = rest.trim();
    if !rest.is_empty() {
        let quoted = rest
            .strip_prefix("COOKIEFILE=")
            .ok_or(ControlError::Protocol("unexpected field in AUTH line"))?;
        let path = unquote(quoted).ok_or(ControlError::Protocol("invalid COOKIEFILE value"))?;
        info.cookie_file = Some(PathBuf::from(path));
    }
    Ok(info)
}

/// Decode a control-spec `QuotedString` that must span all of `text`.
///
/// Backslash escapes: `\n`, `\t`, `\r`, octal `\0`..`\377` (C escapes, as
/// Tor writes them), and a backslash before any other byte is that byte.
fn unquote(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                return if i == bytes.len() - 1 {
                    String::from_utf8(out).ok()
                } else {
                    None
                };
            }
            b'\\' => {
                i += 1;
                match *bytes.get(i)? {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'0'..=b'7' => {
                        let mut value = 0u32;
                        let mut digits = 0;
                        while digits < 3 && i < bytes.len() && (b'0'..=b'7').contains(&bytes[i]) {
                            value = value * 8 + u32::from(bytes[i] - b'0');
                            i += 1;
                            digits += 1;
                        }
                        out.push(u8::try_from(value).ok()?);
                        continue;
                    }
                    other => out.push(other),
                }
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    async fn read_one(server_bytes: &'static [u8]) -> Result<Reply, ControlError> {
        let (client, mut server) = duplex(1024);
        server.write_all(server_bytes).await.unwrap();
        drop(server);
        TorControl::new(client).read_reply().await
    }

    #[tokio::test]
    async fn reads_multi_line_reply() {
        let reply = read_one(b"250-ServiceID=abc\r\n250 OK\r\n").await.unwrap();
        assert_eq!(
            reply,
            Reply {
                code: 250,
                lines: vec!["ServiceID=abc".into(), "OK".into()]
            }
        );
    }

    #[tokio::test]
    async fn error_status_is_reported() {
        let err = read_one(b"515 Authentication failed\r\n")
            .await
            .unwrap()
            .expect_ok()
            .unwrap_err();
        assert!(
            matches!(&err, ControlError::Status { code: 515, message } if message == "Authentication failed"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn eof_mid_reply_is_an_error() {
        for bytes in [&b""[..], b"250-PROTOCOLINFO 1\r\n", b"250 O"] {
            let (client, mut server) = duplex(1024);
            server.write_all(bytes).await.unwrap();
            drop(server);
            let err = TorControl::new(client).read_reply().await.unwrap_err();
            assert!(
                matches!(&err, ControlError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof),
                "{bytes:?}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_replies_are_rejected() {
        for bytes in [
            &b"25 OK\r\n"[..],
            b"2x0 OK\r\n",
            b"250\r\n",
            b"250*OK\r\n",
            b"250-a\r\n251 b\r\n",
            b"250+data\r\n.\r\n250 OK\r\n",
            b"250 \xff\r\n",
        ] {
            let err = read_one(bytes).await.unwrap_err();
            assert!(
                matches!(err, ControlError::Protocol(_)),
                "{bytes:?}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn oversized_reply_is_rejected() {
        let (client, mut server) = duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            let line = format!("250-{}\r\n", "a".repeat(1000));
            for _ in 0..(MAX_REPLY_BYTES / line.len() + 2) {
                if server.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let err = TorControl::new(client).read_reply().await.unwrap_err();
        assert!(
            matches!(err, ControlError::Protocol("reply too large")),
            "{err:?}"
        );
        writer.abort();
    }

    fn lines(auth: &str) -> Vec<String> {
        vec![
            "PROTOCOLINFO 1".into(),
            auth.into(),
            "VERSION Tor=\"0.4.8.10\"".into(),
            "OK".into(),
        ]
    }

    #[test]
    fn parses_protocol_info() {
        assert_eq!(
            parse_protocol_info(&lines("AUTH METHODS=NULL")).unwrap(),
            ProtocolInfo {
                null: true,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_protocol_info(&lines(
                "AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/var/run/tor/control.authcookie\""
            ))
            .unwrap(),
            ProtocolInfo {
                null: false,
                cookie: true,
                safe_cookie: true,
                cookie_file: Some("/var/run/tor/control.authcookie".into()),
            }
        );
        // Unknown methods are ignored.
        assert_eq!(
            parse_protocol_info(&lines("AUTH METHODS=HASHEDPASSWORD,FUTURE")).unwrap(),
            ProtocolInfo::default()
        );
        for bad in [
            vec![
                "PROTOCOLINFO 2".into(),
                "AUTH METHODS=NULL".into(),
                "OK".into(),
            ],
            vec!["PROTOCOLINFO 1".into(), "AUTH METHODS=NULL".into()],
            vec![
                "PROTOCOLINFO 1".into(),
                "VERSION Tor=\"x\"".into(),
                "OK".into(),
            ],
            lines("AUTH METHODS=COOKIE OTHER=1"),
            lines("AUTH METHODS=COOKIE COOKIEFILE=/unquoted"),
            lines("AUTH METHODS=COOKIE COOKIEFILE=\"/a\" trailing"),
        ] {
            assert!(parse_protocol_info(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unquotes_control_strings() {
        assert_eq!(unquote("\"\"").as_deref(), Some(""));
        assert_eq!(unquote("\"/a b/c\"").as_deref(), Some("/a b/c"));
        assert_eq!(unquote(r#""a\"b\\c""#).as_deref(), Some("a\"b\\c"));
        assert_eq!(unquote(r#""\n\t\r""#).as_deref(), Some("\n\t\r"));
        assert_eq!(unquote(r#""\101\60x\7""#).as_deref(), Some("A0x\u{7}"));
        assert_eq!(unquote(r#""\q""#).as_deref(), Some("q"));
        assert_eq!(unquote(r#""\303\251""#).as_deref(), Some("é"));
        for bad in [
            "",
            "abc",
            "\"abc",
            "\"a\"b",
            r#""\"#,
            r#""\400""#,
            r#""\377""#,
        ] {
            assert_eq!(unquote(bad), None, "{bad:?}");
        }
    }

    /// Fake Tor: for each canned reply, read one request line and answer it.
    /// Returns every byte the client sent.
    async fn fake_tor(server: tokio::io::DuplexStream, replies: Vec<String>) -> Vec<u8> {
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

    /// Wire bytes pinned to what torut 0.2.1 sent for the same inputs
    /// (RFC 8032 TEST 1 seed), captured before torut was removed.
    #[tokio::test]
    async fn add_onion_sends_torut_bytes() {
        let seed: [u8; 32] = data_encoding::HEXLOWER
            .decode(b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
        let (client, server) = duplex(4096);
        let server = tokio::spawn(fake_tor(
            server,
            vec!["250-ServiceID=25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid\r\n250 OK\r\n".into()],
        ));
        let service_id = TorControl::new(client)
            .add_onion_v3(
                &ExpandedSecretKey::from_seed(&seed),
                9999,
                "127.0.0.1:43210".parse().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            service_id.as_deref(),
            Some("25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid")
        );
        assert_eq!(
            String::from_utf8(server.await.unwrap()).unwrap(),
            "ADD_ONION ED25519-V3:MHyDhk8oM8tCei7xwAoBPP3/J2jZgMCjpSDwBpBN6U+bTwr+KAt0aneGhOdUQlAgV7dHOgPwj5b1o46Sh+Afjw== Flags=DiscardPK Port=9999,127.0.0.1:43210 \r\n"
        );

        // 552: the service already exists on this Tor instance.
        let (client, server) = duplex(4096);
        let server = tokio::spawn(fake_tor(
            server,
            vec!["552 Onion address collision\r\n".into()],
        ));
        let err = TorControl::new(client)
            .add_onion_v3(
                &ExpandedSecretKey::from_seed(&seed),
                9999,
                "127.0.0.1:1".parse().unwrap(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ControlError::Status { code: 552, .. }),
            "{err:?}"
        );
        server.await.unwrap();
    }

    /// The full handshake for `NULL` and plain `COOKIE`, pinned to torut
    /// 0.2.1's bytes. (torut also sent plain `COOKIE` when only `SAFECOOKIE`
    /// was offered; this client now does `SAFECOOKIE`, tested below.)
    #[tokio::test]
    async fn handshake_sends_torut_bytes() {
        let cookie_path = temp_cookie("handshake", 32);
        let quoted = format!("\"{}\"", cookie_path.display());
        let info = |auth: &str| {
            format!(
                "250-PROTOCOLINFO 1\r\n250-{auth}\r\n250-VERSION Tor=\"0.4.8.10\"\r\n250 OK\r\n"
            )
        };
        let cookie_hex = "A5".repeat(32);
        let cases = [
            (
                vec![info("AUTH METHODS=NULL"), "250 OK\r\n".into()],
                "AUTHENTICATE\r\n".to_string(),
            ),
            (
                vec![
                    info(&format!("AUTH METHODS=COOKIE COOKIEFILE={quoted}")),
                    "250 OK\r\n".into(),
                ],
                format!("AUTHENTICATE {cookie_hex}\r\n"),
            ),
            (vec![info("AUTH METHODS=HASHEDPASSWORD")], String::new()),
        ];
        for (replies, expected_auth) in cases {
            let (client, server) = duplex(4096);
            let server = tokio::spawn(fake_tor(server, replies));
            let mut conn = TorControl::new(client);
            let info = conn.protocol_info().await.unwrap();
            if let Some(auth) = info.auth_data().await.unwrap() {
                conn.authenticate(&auth).await.unwrap();
            }
            assert_eq!(
                String::from_utf8(server.await.unwrap()).unwrap(),
                format!("PROTOCOLINFO 1\r\n{expected_auth}")
            );
        }

        // A rejected AUTHENTICATE is an error.
        let (client, server) = duplex(4096);
        let server = tokio::spawn(fake_tor(
            server,
            vec!["515 Authentication failed\r\n".into()],
        ));
        let err = TorControl::new(client)
            .authenticate(&AuthData::Null)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ControlError::Status { code: 515, .. }),
            "{err:?}"
        );
        server.await.unwrap();
    }

    fn temp_cookie(name: &str, len: usize) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("arachne-tor-control-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, vec![0xa5; len]).unwrap();
        path
    }

    /// `NULL` first, then `SAFECOOKIE`, then plain `COOKIE`.
    #[tokio::test]
    async fn chooses_auth_method() {
        let cookie_file = Some(temp_cookie("cookie", 32));
        let cookie = Some(AuthData::Cookie([0xa5; 32]));
        let safe_cookie = Some(AuthData::SafeCookie([0xa5; 32]));
        let info = |null, cookie, safe_cookie, cookie_file: &Option<PathBuf>| ProtocolInfo {
            null,
            cookie,
            safe_cookie,
            cookie_file: cookie_file.clone(),
        };
        assert_eq!(
            info(true, true, true, &cookie_file)
                .auth_data()
                .await
                .unwrap(),
            Some(AuthData::Null)
        );
        assert_eq!(
            info(false, false, true, &cookie_file)
                .auth_data()
                .await
                .unwrap(),
            safe_cookie
        );
        // SAFECOOKIE is preferred when Tor offers both cookie methods.
        assert_eq!(
            info(false, true, true, &cookie_file)
                .auth_data()
                .await
                .unwrap(),
            safe_cookie
        );
        assert_eq!(
            info(false, true, false, &cookie_file)
                .auth_data()
                .await
                .unwrap(),
            cookie
        );
        assert_eq!(
            info(false, true, true, &None).auth_data().await.unwrap(),
            None
        );
        assert_eq!(
            info(false, false, false, &cookie_file)
                .auth_data()
                .await
                .unwrap(),
            None
        );

        // The cookie file must be exactly 32 bytes, for both cookie methods.
        for (name, len) in [("empty", 0), ("short", 31), ("long", 33), ("huge", 4096)] {
            let path = Some(temp_cookie(name, len));
            for (cookie, safe_cookie) in [(true, false), (false, true), (true, true)] {
                assert!(
                    info(false, cookie, safe_cookie, &path)
                        .auth_data()
                        .await
                        .is_err(),
                    "{name}: cookie={cookie} safe_cookie={safe_cookie}"
                );
            }
        }
        let missing = Some(PathBuf::from("/nonexistent/arachne/cookie"));
        assert!(
            info(false, true, false, &missing)
                .auth_data()
                .await
                .is_err()
        );
    }

    const SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
    const CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

    /// HMAC-SHA256 (RFC 2104) written out with plain SHA-256, so that the
    /// expected values do not come from the `hmac` crate the client uses.
    fn test_hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut block = [0u8; 64];
        if key.len() > block.len() {
            block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let ipad: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
        let inner = Sha256::new()
            .chain_update(&ipad)
            .chain_update(msg)
            .finalize();
        Sha256::new()
            .chain_update(&opad)
            .chain_update(inner)
            .finalize()
            .into()
    }

    /// (SERVERHASH, client AUTHENTICATE hash) as control-spec 3.24 defines.
    fn safe_cookie_hashes(
        cookie: &[u8],
        client_nonce: &[u8],
        server_nonce: &[u8],
    ) -> ([u8; 32], [u8; 32]) {
        let msg = [cookie, client_nonce, server_nonce].concat();
        (
            test_hmac_sha256(SERVER_KEY, &msg),
            test_hmac_sha256(CLIENT_KEY, &msg),
        )
    }

    #[test]
    fn test_hmac_is_rfc4231() {
        // RFC 4231 test case 2.
        assert_eq!(
            data_encoding::HEXLOWER
                .encode(&test_hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// Like `fake_tor`, then reads everything else the client sends until it
    /// closes the connection.
    async fn fake_tor_drain(server: tokio::io::DuplexStream, replies: Vec<String>) -> Vec<u8> {
        let mut reader = BufReader::new(server);
        let mut transcript = Vec::new();
        for reply in replies {
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).await.unwrap();
            transcript.extend_from_slice(&line);
            reader.get_mut().write_all(reply.as_bytes()).await.unwrap();
        }
        reader.read_to_end(&mut transcript).await.unwrap();
        transcript
    }

    const TEST_CLIENT_NONCE: [u8; 32] = [0x11; 32];
    const TEST_SERVER_NONCE: [u8; 32] = [0x22; 32];

    fn test_cookie() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    fn challenge_reply(server_hash: &str, server_nonce: &str) -> String {
        format!("250 AUTHCHALLENGE SERVERHASH={server_hash} SERVERNONCE={server_nonce}\r\n")
    }

    /// Run `authenticate_safe_cookie` with the test cookie and nonce against
    /// canned replies. Returns the result and everything the client sent.
    async fn run_safe_cookie(replies: Vec<String>) -> (Result<(), ControlError>, String) {
        let (client, server) = duplex(4096);
        let server = tokio::spawn(fake_tor_drain(server, replies));
        let mut conn = TorControl::new(client);
        // A client that sends an unexpected command waits for a reply that
        // never comes; report that as a timeout instead of hanging.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.authenticate_safe_cookie(&test_cookie(), &TEST_CLIENT_NONCE),
        )
        .await
        .unwrap_or_else(|_| Err(ControlError::Io(io::ErrorKind::TimedOut.into())));
        drop(conn);
        let transcript = String::from_utf8(server.await.unwrap()).unwrap();
        (result, transcript)
    }

    fn expected_challenge() -> String {
        format!(
            "AUTHCHALLENGE SAFECOOKIE {}\r\n",
            HEXUPPER.encode(&TEST_CLIENT_NONCE)
        )
    }

    #[tokio::test]
    async fn safe_cookie_happy_path() {
        let (server_hash, client_hash) =
            safe_cookie_hashes(&test_cookie(), &TEST_CLIENT_NONCE, &TEST_SERVER_NONCE);
        // The same values from Python's `hmac` module, as a second check.
        assert_eq!(
            HEXUPPER.encode(&server_hash),
            "2AECBF4D284BEFDDBBACC3817B41959EDA061AC7E156DB0C734CB28AA5E903ED"
        );
        assert_eq!(
            HEXUPPER.encode(&client_hash),
            "EEA571786A3FD103B6AA1FFA46249C4C850C509D0C84C550ED9E41477511D2BA"
        );
        // Tor sends upper-case hex; lower case is accepted too.
        for encoding in [HEXUPPER, data_encoding::HEXLOWER] {
            let (result, transcript) = run_safe_cookie(vec![
                challenge_reply(
                    &encoding.encode(&server_hash),
                    &encoding.encode(&TEST_SERVER_NONCE),
                ),
                "250 OK\r\n".into(),
            ])
            .await;
            result.unwrap();
            assert_eq!(
                transcript,
                format!(
                    "{}AUTHENTICATE {}\r\n",
                    expected_challenge(),
                    HEXUPPER.encode(&client_hash)
                )
            );
        }

        // Tor rejects the AUTHENTICATE: the error is reported.
        let (result, _) = run_safe_cookie(vec![
            challenge_reply(
                &HEXUPPER.encode(&server_hash),
                &HEXUPPER.encode(&TEST_SERVER_NONCE),
            ),
            "515 Authentication failed\r\n".into(),
        ])
        .await;
        assert!(
            matches!(result, Err(ControlError::Status { code: 515, .. })),
            "{result:?}"
        );
    }

    /// A wrong SERVERHASH means the peer does not know the cookie: fail
    /// closed and never send AUTHENTICATE.
    #[tokio::test]
    async fn safe_cookie_server_hash_mismatch_fails_closed() {
        let msg = [&test_cookie()[..], &TEST_CLIENT_NONCE, &TEST_SERVER_NONCE].concat();
        let (server_hash, client_hash) =
            safe_cookie_hashes(&test_cookie(), &TEST_CLIENT_NONCE, &TEST_SERVER_NONCE);
        let mut flipped = server_hash;
        flipped[31] ^= 1;
        let wrong_hashes = [
            flipped,
            // The controller-to-server hash reflected back.
            client_hash,
            // Right key, wrong cookie.
            test_hmac_sha256(
                SERVER_KEY,
                &[&[0u8; 32][..], &TEST_CLIENT_NONCE, &TEST_SERVER_NONCE].concat(),
            ),
            // Right key and cookie, nonces swapped.
            test_hmac_sha256(
                SERVER_KEY,
                &[&test_cookie()[..], &TEST_SERVER_NONCE, &TEST_CLIENT_NONCE].concat(),
            ),
            test_hmac_sha256(b"", &msg),
        ];
        for wrong in wrong_hashes {
            let (result, transcript) = run_safe_cookie(vec![challenge_reply(
                &HEXUPPER.encode(&wrong),
                &HEXUPPER.encode(&TEST_SERVER_NONCE),
            )])
            .await;
            assert!(
                matches!(result, Err(ControlError::Protocol(_))),
                "{result:?}"
            );
            assert_eq!(transcript, expected_challenge());
        }
    }

    #[tokio::test]
    async fn safe_cookie_malformed_challenge_is_rejected() {
        let (server_hash, _) =
            safe_cookie_hashes(&test_cookie(), &TEST_CLIENT_NONCE, &TEST_SERVER_NONCE);
        let hash = HEXUPPER.encode(&server_hash);
        let nonce = HEXUPPER.encode(&TEST_SERVER_NONCE);
        let replies = [
            format!("250 AUTHCHALLENGE SERVERHASH={hash}\r\n"),
            format!("250 AUTHCHALLENGE SERVERNONCE={nonce}\r\n"),
            "250 AUTHCHALLENGE\r\n".into(),
            "250 OK\r\n".into(),
            format!("250 AUTHCHALLENGEX SERVERHASH={hash} SERVERNONCE={nonce}\r\n"),
            format!("250 SERVERHASH={hash} SERVERNONCE={nonce}\r\n"),
            challenge_reply(&hash[..62], &nonce),
            challenge_reply(&format!("{hash}00"), &nonce),
            challenge_reply(&hash[..63], &nonce),
            challenge_reply(&format!("ZZ{}", &hash[2..]), &nonce),
            challenge_reply(&hash, &nonce[..62]),
            challenge_reply(&hash, &format!("{nonce}00")),
            challenge_reply(&hash, ""),
            challenge_reply("", &nonce),
            format!(
                "250 AUTHCHALLENGE SERVERHASH={hash} SERVERHASH={hash} SERVERNONCE={nonce}\r\n"
            ),
            format!(
                "250 AUTHCHALLENGE SERVERHASH={hash} SERVERNONCE={nonce} SERVERNONCE={nonce}\r\n"
            ),
            format!("250-AUTHCHALLENGE SERVERHASH={hash} SERVERNONCE={nonce}\r\n250 OK\r\n"),
            "512 Invalid argument\r\n".into(),
        ];
        for reply in replies {
            let (result, transcript) = run_safe_cookie(vec![reply.clone()]).await;
            assert!(
                matches!(
                    result,
                    Err(ControlError::Protocol(_) | ControlError::Status { .. })
                ),
                "{reply:?}: {result:?}"
            );
            assert_eq!(transcript, expected_challenge(), "{reply:?}");
        }
    }

    /// End to end through `protocol_info`, `auth_data` and `authenticate`
    /// with a random client nonce: a fake Tor that offers both cookie
    /// methods checks the SAFECOOKIE exchange. Each run uses a fresh nonce.
    #[tokio::test]
    async fn handshake_prefers_safe_cookie() {
        let cookie_path = temp_cookie("safe-handshake", 32);
        let mut nonces = Vec::new();
        for _ in 0..2 {
            let quoted = format!("\"{}\"", cookie_path.display());
            let (client, server) = duplex(4096);
            let server = tokio::spawn(async move {
                let mut reader = BufReader::new(server);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                assert_eq!(line, "PROTOCOLINFO 1\r\n");
                let info = format!(
                    "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE={quoted}\r\n250-VERSION Tor=\"0.4.8.10\"\r\n250 OK\r\n"
                );
                reader.get_mut().write_all(info.as_bytes()).await.unwrap();

                line.clear();
                reader.read_line(&mut line).await.unwrap();
                let nonce_hex = line
                    .strip_prefix("AUTHCHALLENGE SAFECOOKIE ")
                    .and_then(|rest| rest.strip_suffix("\r\n"))
                    .unwrap_or_else(|| panic!("not an AUTHCHALLENGE: {line:?}"));
                let client_nonce = HEXUPPER.decode(nonce_hex.as_bytes()).unwrap();
                assert_eq!(client_nonce.len(), 32);
                let (server_hash, client_hash) =
                    safe_cookie_hashes(&[0xa5; 32], &client_nonce, &TEST_SERVER_NONCE);
                let reply = challenge_reply(
                    &HEXUPPER.encode(&server_hash),
                    &HEXUPPER.encode(&TEST_SERVER_NONCE),
                );
                reader.get_mut().write_all(reply.as_bytes()).await.unwrap();

                line.clear();
                reader.read_line(&mut line).await.unwrap();
                assert_eq!(
                    line,
                    format!("AUTHENTICATE {}\r\n", HEXUPPER.encode(&client_hash))
                );
                reader.get_mut().write_all(b"250 OK\r\n").await.unwrap();
                client_nonce
            });
            let mut conn = TorControl::new(client);
            let info = conn.protocol_info().await.unwrap();
            let auth = info.auth_data().await.unwrap().unwrap();
            assert_eq!(auth, AuthData::SafeCookie([0xa5; 32]));
            conn.authenticate(&auth).await.unwrap();
            nonces.push(server.await.unwrap());
        }
        assert_ne!(nonces[0], nonces[1], "client nonce must be random");
    }

    /// Against a real Tor: `tor --ControlPort 9051 --CookieAuthentication 1`
    /// (SAFECOOKIE) or `--CookieAuthentication 0` (NULL). Tor itself must
    /// report the onion address this crate derives from the key.
    #[tokio::test]
    #[ignore = "requires a local Tor daemon with ControlPort 9051"]
    async fn live_tor_accepts_key_and_reports_same_service_id() {
        let stream = tokio::net::TcpStream::connect("127.0.0.1:9051")
            .await
            .unwrap();
        let mut conn = TorControl::new(stream);
        let info = conn.protocol_info().await.unwrap();
        let auth = info
            .auth_data()
            .await
            .unwrap()
            .expect("usable Tor auth method");
        eprintln!("Tor auth method: {auth:?}");
        conn.authenticate(&auth).await.unwrap();
        let secret = iroh::SecretKey::generate();
        let key = ExpandedSecretKey::from_seed(&secret.to_bytes());
        let service_id = conn
            .add_onion_v3(&key, 9999, "127.0.0.1:9".parse().unwrap())
            .await
            .unwrap();
        let expected = crate::onion::OnionAddressV3::from_public_key(secret.public().as_bytes());
        assert_eq!(service_id, Some(expected.service_id()));
    }
}
