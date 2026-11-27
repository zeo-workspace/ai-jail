//! HTTPS credential injection (Zeo proposal §6.53, 2026-11-27).
//!
//! `--secret` keeps a credential out of the sandbox: the child sees a
//! placeholder, and the egress proxy puts the real value into requests
//! to the binding's hosts. Plain HTTP was enough to see the request head;
//! HTTPS was not -- a CONNECT tunnel is opaque, so a placeholder sent over
//! TLS went out unchanged and authentication failed.
//!
//! This module lets the proxy open exactly those tunnels. At launch it
//! generates a CA whose key lives only in this process's memory and whose
//! name constraints permit the secret-bound hosts alone, so even a copy of
//! the key could not impersonate any other site. The sandbox trusts that
//! CA through a bundle file (the system roots plus the CA) mounted next to
//! the proxy socket and named by the usual CA environment variables. For a
//! CONNECT to a secret-bound host the proxy answers as that host with a
//! short-lived leaf certificate, decrypts one request, rewrites its head,
//! and re-originates it over real TLS to the real host. Every other tunnel
//! stays opaque and untouched.
//!
//! The private keys never reach disk, a log or the sandbox; the files
//! written here hold public certificates only.

use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// How long a leaf certificate is valid. Short, because nothing outside
/// this launch ever needs it; re-minted when it runs out.
const LEAF_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// How long the CA is valid: well past any session, and it dies with the
/// process anyway.
const CA_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Clock skew allowed between the supervisor and the sandbox.
const BACKDATE: Duration = Duration::from_secs(5 * 60);

/// Where the sandbox finds the CA, relative to the proxy socket's
/// host-side path ([`bundle_paths`]) and inside the sandbox.
pub(crate) const IN_SANDBOX_BUNDLE_PATH: &str = "/tmp/.ai-jail-ca-bundle.pem";
pub(crate) const IN_SANDBOX_CA_PATH: &str = "/tmp/.ai-jail-ca.pem";

/// System trust bundles, in the order the common distributions place
/// them. The first that exists is copied into the sandbox's bundle so
/// every tunnel that is not intercepted keeps verifying as before.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// The launch's injection CA and the leaf configurations minted from it.
pub(crate) struct InjectCa {
    params: CertificateParams,
    key: KeyPair,
    cert_pem: String,
    hosts: Vec<String>,
    leaves: Mutex<HashMap<String, (SystemTime, Arc<rustls::ServerConfig>)>>,
}

impl std::fmt::Debug for InjectCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InjectCa")
            .field("hosts", &self.hosts)
            .field("key", &"[in memory only]")
            .finish()
    }
}

impl InjectCa {
    /// A CA that may sign certificates for `hosts` (and their
    /// subdomains, which is how name constraints read a DNS name) and
    /// nothing else.
    pub(crate) fn generate(hosts: &[String]) -> Result<Self, String> {
        let mut hosts: Vec<String> = hosts
            .iter()
            .map(|h| h.trim_end_matches('.').to_lowercase())
            .collect();
        hosts.sort();
        hosts.dedup();
        if hosts.is_empty() {
            return Err("the injection CA needs at least one host".into());
        }
        let key = KeyPair::generate().map_err(|e| {
            format!("cannot generate the injection CA key: {e}")
        })?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| format!("injection CA parameters: {e}"))?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "ai-jail per-launch secret injection CA");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.name_constraints = Some(name_constraints(&hosts));
        let now = SystemTime::now();
        params.not_before = (now - BACKDATE).into();
        params.not_after = (now + CA_LIFETIME).into();
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("cannot sign the injection CA: {e}"))?;
        Ok(InjectCa {
            cert_pem: cert.pem(),
            params,
            key,
            hosts,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate (public), PEM.
    pub(crate) fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Whether the CA may speak for `host`: only the secret-bound hosts
    /// themselves, never a sibling the name constraint would also allow.
    pub(crate) fn covers(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_lowercase();
        self.hosts.contains(&host)
    }

    /// A TLS server configuration presenting a fresh leaf for `host`,
    /// minted on first use and reused until it nears expiry. HTTP/1.1
    /// only, so the decrypted stream is a request head the proxy can read
    /// (an HTTP/2 client falls back, as ALPN allows).
    pub(crate) fn server_config(
        &self,
        host: &str,
    ) -> Result<Arc<rustls::ServerConfig>, String> {
        let host = host.trim_end_matches('.').to_lowercase();
        if !self.covers(&host) {
            return Err(format!("{host} is not a secret-bound host"));
        }
        let now = SystemTime::now();
        let mut leaves =
            self.leaves.lock().map_err(|_| "leaf cache poisoned")?;
        if let Some((expires, config)) = leaves.get(&host)
            && *expires > now + BACKDATE
        {
            return Ok(Arc::clone(config));
        }
        let (expires, config) = self.mint(&host, now)?;
        let config = Arc::new(config);
        leaves.insert(host, (expires, Arc::clone(&config)));
        Ok(config)
    }

    fn mint(
        &self,
        host: &str,
        now: SystemTime,
    ) -> Result<(SystemTime, rustls::ServerConfig), String> {
        let leaf_key = KeyPair::generate()
            .map_err(|e| format!("cannot generate a leaf key: {e}"))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("leaf parameters for {host}: {e}"))?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let expires = now + LEAF_LIFETIME;
        params.not_before = (now - BACKDATE).into();
        params.not_after = expires.into();
        let issuer = Issuer::from_params(&self.params, &self.key);
        let leaf = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| format!("cannot sign the leaf for {host}: {e}"))?;
        let chain: Vec<CertificateDer<'static>> = vec![leaf.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            leaf_key.serialize_der(),
        ));
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| format!("TLS server configuration for {host}: {e}"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok((expires, config))
    }
}

/// The CA may sign for the bound hosts and nothing else. A DNS name
/// permits that name and its subdomains (RFC 5280 §4.2.1.10; `covers`
/// narrows interception to the exact hosts); an IP literal permits that
/// one address. A name form with no permitted entry is otherwise
/// unconstrained, so when no IP literal is bound every address is
/// excluded outright -- the CA can never vouch for an IP.
fn name_constraints(hosts: &[String]) -> NameConstraints {
    let mut permitted = Vec::new();
    let mut any_ip = false;
    for host in hosts {
        match host.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                any_ip = true;
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                permitted.push(GeneralSubtree::IpAddress(
                    CidrSubnet::from_addr_prefix(ip, prefix),
                ));
            }
            Err(_) => permitted.push(GeneralSubtree::DnsName(host.clone())),
        }
    }
    let excluded = if any_ip {
        Vec::new()
    } else {
        vec![
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([0; 4], 0)),
            GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix([0; 16], 0)),
        ]
    };
    NameConstraints {
        permitted_subtrees: permitted,
        excluded_subtrees: excluded,
    }
}

/// Host-side paths of the two files the sandbox mounts, derived from the
/// proxy socket's path so they share its per-launch nonce and its
/// lifetime: (bundle = system roots + CA, CA alone).
pub(crate) fn bundle_paths(proxy_socket: &Path) -> (PathBuf, PathBuf) {
    let base = proxy_socket.as_os_str().to_string_lossy();
    (
        PathBuf::from(format!("{base}.ca-bundle.pem")),
        PathBuf::from(format!("{base}.ca.pem")),
    )
}

/// Write the bundle and the CA certificate next to the proxy socket,
/// mode 0600 and refusing to follow or reuse an existing path, so a
/// planted file or symlink in the temp directory cannot stand in for
/// them. The bundle starts with the first system bundle found; without
/// one, the sandbox's non-intercepted tunnels would fail verification,
/// so that is an error rather than a silent CA-only bundle.
pub(crate) fn write_bundle(
    ca: &InjectCa,
    proxy_socket: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    let system = SYSTEM_BUNDLES
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .ok_or_else(|| {
            format!(
                "--secret over HTTPS needs the system CA bundle, found none of {}",
                SYSTEM_BUNDLES.join(", ")
            )
        })?;
    let (bundle_path, ca_path) = bundle_paths(proxy_socket);
    let mut bundle = system;
    if !bundle.ends_with('\n') {
        bundle.push('\n');
    }
    bundle.push_str(ca.cert_pem());
    write_new_private(&bundle_path, bundle.as_bytes())?;
    if let Err(e) = write_new_private(&ca_path, ca.cert_pem().as_bytes()) {
        let _ = std::fs::remove_file(&bundle_path);
        return Err(e);
    }
    Ok((bundle_path, ca_path))
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Remove the two files ([`write_bundle`]); quiet, it runs on teardown.
pub(crate) fn remove_bundle(proxy_socket: &Path) {
    let (bundle, ca) = bundle_paths(proxy_socket);
    let _ = std::fs::remove_file(bundle);
    let _ = std::fs::remove_file(ca);
}

/// The environment that points the sandbox's TLS clients at the bundle:
/// OpenSSL, curl, Python requests and git read a whole bundle; Node adds
/// extra CAs to its built-in roots, so it gets the CA alone.
pub(crate) fn env_vars() -> Vec<(String, String)> {
    let bundle = IN_SANDBOX_BUNDLE_PATH.to_string();
    vec![
        ("SSL_CERT_FILE".into(), bundle.clone()),
        ("CURL_CA_BUNDLE".into(), bundle.clone()),
        ("REQUESTS_CA_BUNDLE".into(), bundle.clone()),
        ("GIT_SSL_CAINFO".into(), bundle),
        ("NODE_EXTRA_CA_CERTS".into(), IN_SANDBOX_CA_PATH.into()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(list: &[&str]) -> Vec<String> {
        list.iter().map(|h| h.to_string()).collect()
    }

    #[test]
    fn the_ca_covers_its_hosts_alone() {
        let ca = InjectCa::generate(&hosts(&["API.github.com.", "github.com"]))
            .unwrap();
        assert!(ca.covers("api.github.com"));
        assert!(ca.covers("github.com"));
        // A subdomain the name constraint would allow is still refused:
        // the proxy intercepts exactly the bound hosts.
        assert!(!ca.covers("evil.github.com"));
        assert!(!ca.covers("example.com"));
        assert!(ca.server_config("example.com").is_err());
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!format!("{ca:?}").contains("PRIVATE"));
        assert!(InjectCa::generate(&[]).is_err());
    }

    #[test]
    fn a_leaf_is_minted_once_and_speaks_http_1_1_only() {
        let ca = InjectCa::generate(&hosts(&["api.example.com"])).unwrap();
        let first = ca.server_config("api.example.com").unwrap();
        let again = ca.server_config("API.example.com.").unwrap();
        assert!(Arc::ptr_eq(&first, &again), "cached per host");
        assert_eq!(first.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn a_client_trusting_the_ca_completes_a_handshake_with_the_leaf() {
        // The whole chain, in memory: a rustls client that trusts only the
        // CA connects to the leaf's server config for the bound host.
        let ca = InjectCa::generate(&hosts(&["api.example.com"])).unwrap();
        let server_config = ca.server_config("api.example.com").unwrap();
        let ca_der = rustls_pemfile_like(ca.cert_pem());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name =
            rustls::pki_types::ServerName::try_from("api.example.com").unwrap();
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), name)
                .unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut buf.as_slice()).unwrap();
                server.process_new_packets().unwrap();
            }
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut buf.as_slice()).unwrap();
                client.process_new_packets().unwrap();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return;
            }
        }
        panic!("the handshake did not complete");
    }

    /// The one certificate in a PEM string, as DER (tests only).
    fn rustls_pemfile_like(pem: &str) -> CertificateDer<'static> {
        let body: String =
            pem.lines().filter(|l| !l.starts_with("-----")).collect();
        CertificateDer::from(decode_b64(&body))
    }

    fn decode_b64(text: &str) -> Vec<u8> {
        const A: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0_u32;
        let mut n = 0;
        let mut out = Vec::new();
        for c in text.bytes().filter(|c| *c != b'=') {
            let v = A.iter().position(|a| *a == c).unwrap() as u32;
            bits = (bits << 6) | v;
            n += 6;
            if n >= 8 {
                n -= 8;
                out.push((bits >> n) as u8);
            }
        }
        out
    }

    #[test]
    fn the_bundle_files_are_private_new_and_removed() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-tls-inject-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("proxy.sock");
        let ca = InjectCa::generate(&hosts(&["api.example.com"])).unwrap();
        if SYSTEM_BUNDLES.iter().all(|p| !Path::new(p).exists()) {
            assert!(write_bundle(&ca, &socket).is_err());
            return;
        }
        let (bundle, ca_file) = write_bundle(&ca, &socket).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        for path in [&bundle, &ca_file] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", path.display());
        }
        let text = std::fs::read_to_string(&bundle).unwrap();
        assert!(text.ends_with(ca.cert_pem()));
        assert!(!text.contains("PRIVATE KEY"));
        // A second write never reuses an existing path.
        assert!(write_bundle(&ca, &socket).is_err());
        remove_bundle(&socket);
        assert!(!bundle.exists() && !ca_file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_sandbox_env_names_the_mounted_files() {
        let vars = env_vars();
        let get = |k: &str| {
            vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
        };
        assert_eq!(get("SSL_CERT_FILE"), Some(IN_SANDBOX_BUNDLE_PATH));
        assert_eq!(get("GIT_SSL_CAINFO"), Some(IN_SANDBOX_BUNDLE_PATH));
        assert_eq!(get("NODE_EXTRA_CA_CERTS"), Some(IN_SANDBOX_CA_PATH));
    }
}
