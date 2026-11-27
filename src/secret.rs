//! Phantom credential injection (Part 2 of the filtered-egress plan,
//! issue #135).
//!
//! The sandbox environment holds a *placeholder* for each bound secret;
//! the real value exists only in supervisor memory. The egress proxy
//! substitutes placeholder -> real only inside the request head of a
//! request that terminates at one of the binding's allowlisted hosts:
//! an absolute-form plain-HTTP request, or (Linux) an HTTPS request the
//! proxy decrypts with a per-launch CA ([`crate::tls_inject`]). Every
//! other CONNECT tunnel stays opaque and untouched.
//!
//! A placeholder is `AIJAIL-PHANTOM-<16 hex>`, derived from the key, the
//! value and a per-launch session nonce: two launches never share one,
//! so a placeholder seen in one session's logs says nothing about the
//! next. It is shaped so it can never collide with a real token, and is
//! harmless when printed by dry-run or `ai-jail status`. It is not a
//! credential -- knowing it authorizes nothing.
//!
//! A key may name several hosts (`--secret KEY=a.example,b.example`):
//! each host gets its own binding, all sharing the key's placeholder.

/// One bound secret: the env var `key`, the `placeholder` the sandbox
/// sees, the `real` value that never leaves the supervisor, and the
/// allowlisted `host` whose terminated requests may carry it.
#[derive(Clone)]
pub(crate) struct SecretBinding {
    pub key: String,
    pub placeholder: String,
    pub real: String,
    pub host: String,
}

impl SecretBinding {
    #[cfg(test)]
    pub(crate) fn new(key: &str, real: &str, host: &str) -> Self {
        Self::with_session(key, real, host, "")
    }

    /// The binding for one launch: `session` is that launch's random
    /// nonce ([`session_nonce`]), so the same key and value get a
    /// different placeholder in every session.
    pub(crate) fn with_session(
        key: &str,
        real: &str,
        host: &str,
        session: &str,
    ) -> Self {
        let digest = crate::audit::sha256_hex(
            format!("{key}:{real}:{session}").as_bytes(),
        );
        SecretBinding {
            key: key.to_string(),
            placeholder: format!("AIJAIL-PHANTOM-{}", &digest[..16]),
            real: real.to_string(),
            host: host.to_string(),
        }
    }
}

// The real value never appears in debug output either.
impl std::fmt::Debug for SecretBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBinding")
            .field("key", &self.key)
            .field("placeholder", &self.placeholder)
            .field("real", &"[redacted]")
            .field("host", &self.host)
            .finish()
    }
}

/// A random per-launch nonce for [`SecretBinding::with_session`]: 16
/// bytes from the system RNG, hex-encoded. Falls back to the clock only
/// if the RNG fails, which on Linux and macOS it does not.
pub(crate) fn session_nonce() -> String {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0_u8; 16];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes = now.to_le_bytes();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The hosts a `secret_hosts` value names: one host, or several
/// separated by commas (`api.github.com,github.com`). Empty items and
/// surrounding spaces are dropped; order is kept and duplicates removed.
pub(crate) fn split_hosts(value: &str) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for host in value.split(',').map(str::trim).filter(|h| !h.is_empty()) {
        if !hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            hosts.push(host.to_string());
        }
    }
    hosts
}

/// Byte-replace every placeholder occurrence in `head` (the request
/// line and headers only -- never the body) with the real value,
/// returning the rewritten bytes and the substitution count for
/// auditing. Multiple bindings stack; a placeholder that never appears
/// costs nothing.
pub(crate) fn rewrite_head(
    head: &[u8],
    bindings: &[SecretBinding],
) -> (Vec<u8>, usize) {
    let (mut out, mut substitutions) = rewrite_basic_auth(head, bindings);
    for binding in bindings {
        let (rewritten, count) = replace_all(
            &out,
            binding.placeholder.as_bytes(),
            binding.real.as_bytes(),
        );
        out = rewritten;
        substitutions += count;
    }
    (out, substitutions)
}

/// `Authorization: Basic` carries `base64(user:password)`, so a
/// placeholder used as the password -- `git push` over HTTPS with a token
/// does exactly that -- is invisible to a byte search. Decode each Basic
/// credential in the head, substitute, and re-encode it. Any other
/// header passes through unchanged; a credential that does not decode,
/// or holds no placeholder, is left byte for byte.
fn rewrite_basic_auth(
    head: &[u8],
    bindings: &[SecretBinding],
) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(head.len());
    let mut substitutions = 0;
    let mut rest = head;
    loop {
        let line_end = find_subslice(rest, b"\r\n").unwrap_or(rest.len());
        let line = &rest[..line_end];
        out.extend_from_slice(&rewrite_basic_line(
            line,
            bindings,
            &mut substitutions,
        ));
        if line_end == rest.len() {
            break;
        }
        out.extend_from_slice(b"\r\n");
        rest = &rest[line_end + 2..];
    }
    (out, substitutions)
}

fn rewrite_basic_line(
    line: &[u8],
    bindings: &[SecretBinding],
    substitutions: &mut usize,
) -> Vec<u8> {
    let Some(colon) = line.iter().position(|b| *b == b':') else {
        return line.to_vec();
    };
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    let is_auth = name.eq_ignore_ascii_case(b"authorization")
        || name.eq_ignore_ascii_case(b"proxy-authorization");
    let trimmed = value.trim_ascii_start();
    let scheme_len = b"basic ".len();
    if !is_auth
        || trimmed.len() <= scheme_len
        || !trimmed[..scheme_len].eq_ignore_ascii_case(b"basic ")
    {
        return line.to_vec();
    }
    let encoded = trimmed[scheme_len..].trim_ascii();
    let Some(decoded) = base64_decode(encoded) else {
        return line.to_vec();
    };
    let mut credential = decoded;
    let mut count = 0;
    for binding in bindings {
        let (rewritten, n) = replace_all(
            &credential,
            binding.placeholder.as_bytes(),
            binding.real.as_bytes(),
        );
        credential = rewritten;
        count += n;
    }
    if count == 0 {
        return line.to_vec();
    }
    *substitutions += count;
    let mut rebuilt = name.to_vec();
    rebuilt.extend_from_slice(b": Basic ");
    rebuilt.extend_from_slice(base64_encode(&credential).as_bytes());
    rebuilt
}

const BASE64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 §4), the alphabet Basic auth
/// uses. Small enough to keep here rather than add a dependency.
fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n =
            (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(BASE64[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The inverse of [`base64_encode`]; `None` for anything that is not
/// canonical padded base64.
fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| BASE64.iter().position(|a| *a == c).map(|p| p as u32);
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let quads = input.len() / 4;
    for (index, quad) in input.chunks(4).enumerate() {
        let last = index + 1 == quads;
        let pad = quad.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0_u32;
        for (i, c) in quad.iter().enumerate() {
            let v = if i >= 4 - pad { 0 } else { value(*c)? };
            n |= v << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// Replace every non-overlapping occurrence of `needle` in `haystack`
/// with `replacement`.
fn replace_all(
    haystack: &[u8],
    needle: &[u8],
    replacement: &[u8],
) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(haystack.len());
    let mut count = 0;
    let mut pos = 0;
    while let Some(at) = find_subslice(&haystack[pos..], needle) {
        out.extend_from_slice(&haystack[pos..pos + at]);
        out.extend_from_slice(replacement);
        pos += at + needle.len();
        count += 1;
    }
    out.extend_from_slice(&haystack[pos..]);
    (out, count)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SecretBinding {
        SecretBinding::new(
            "ANTHROPIC_API_KEY",
            "sk-ant-real",
            "api.anthropic.com",
        )
    }

    #[test]
    fn placeholder_is_deterministic_and_shaped() {
        let a = SecretBinding::new("KEY", "real-value", "example.com");
        let b = SecretBinding::new("KEY", "real-value", "example.com");
        let c = SecretBinding::new("KEY", "other-value", "example.com");
        assert_eq!(a.placeholder, b.placeholder);
        assert_ne!(a.placeholder, c.placeholder);
        assert!(a.placeholder.starts_with("AIJAIL-PHANTOM-"));
        assert_eq!(a.placeholder.len(), "AIJAIL-PHANTOM-".len() + 16);
        // Never leaks the real value's prefix or length.
        assert!(!a.placeholder.contains("real"));
        assert!(!a.placeholder.contains("-value"));
    }

    #[test]
    fn rewrite_head_substitutes_every_occurrence() {
        let b = binding();
        let head = format!(
            "POST /v1/messages HTTP/1.1\r\n\
             x-api-key: {}\r\n\
             authorization: Bearer {}\r\n\
             host: api.anthropic.com\r\n\
             \r\n",
            b.placeholder, b.placeholder
        );
        let (out, count) = rewrite_head(head.as_bytes(), &[binding()]);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(count, 2);
        assert!(!out.contains(&b.placeholder));
        assert_eq!(out.matches("sk-ant-real").count(), 2);
    }

    #[test]
    fn rewrite_head_noop_without_placeholder() {
        let head = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";
        let (out, count) = rewrite_head(head, &[binding()]);
        assert_eq!(count, 0);
        assert_eq!(out, head);
    }

    #[test]
    fn a_session_nonce_changes_the_placeholder() {
        let a = SecretBinding::with_session("KEY", "v", "h.example", "s1");
        let b = SecretBinding::with_session("KEY", "v", "h.example", "s1");
        let c = SecretBinding::with_session("KEY", "v", "h.example", "s2");
        assert_eq!(a.placeholder, b.placeholder);
        assert_ne!(a.placeholder, c.placeholder);
        let (n1, n2) = (session_nonce(), session_nonce());
        assert_eq!(n1.len(), 32);
        assert_ne!(n1, n2);
    }

    #[test]
    fn secret_hosts_value_splits_on_commas() {
        assert_eq!(split_hosts("api.github.com"), ["api.github.com"]);
        assert_eq!(
            split_hosts(" api.github.com, github.com ,,GitHub.com"),
            ["api.github.com", "github.com"]
        );
        assert!(split_hosts(" , ").is_empty());
    }

    #[test]
    fn base64_round_trips_and_refuses_garbage() {
        for raw in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"x-access-token:abc",
        ] {
            if raw.is_empty() {
                continue;
            }
            let encoded = base64_encode(raw);
            assert_eq!(base64_decode(encoded.as_bytes()).as_deref(), Some(raw));
        }
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
        for bad in [&b"abc"[..], b"a===", b"ab=c", b"ab!c", b"YQ==YQ=="] {
            assert_eq!(base64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn basic_auth_carrying_a_placeholder_is_rewritten() {
        // git push over HTTPS: the token is the Basic password.
        let b = binding();
        let credential = base64_encode(
            format!("x-access-token:{}", b.placeholder).as_bytes(),
        );
        let head = format!(
            "POST /org/repo.git/git-receive-pack HTTP/1.1\r\n\
             Host: github.com\r\n\
             Authorization: Basic {credential}\r\n\r\n"
        );
        let (out, count) = rewrite_head(head.as_bytes(), &[binding()]);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(count, 1);
        let expected = base64_encode(b"x-access-token:sk-ant-real");
        assert!(
            out.contains(&format!("Authorization: Basic {expected}\r\n")),
            "{out}"
        );
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn basic_auth_without_a_placeholder_is_left_byte_for_byte() {
        let head = b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\nX-Other: Basic AIJAIL\r\n\r\n";
        let (out, count) = rewrite_head(head, &[binding()]);
        assert_eq!(count, 0);
        assert_eq!(out, head);
    }

    #[test]
    fn rewrite_head_treats_head_as_bytes() {
        // A placeholder straddling a multibyte boundary still matches;
        // non-UTF-8 bytes elsewhere pass through untouched.
        let b = binding();
        let mut head = b"GET / HTTP/1.1\r\nx-k: ".to_vec();
        head.extend_from_slice(&[0xff, 0xfe]);
        head.extend_from_slice(b.placeholder.as_bytes());
        head.extend_from_slice(b"\r\n\r\n");
        let (out, count) = rewrite_head(&head, &[binding()]);
        assert_eq!(count, 1);
        assert!(out.windows(2).any(|w| w == [0xff, 0xfe]));
        assert!(String::from_utf8_lossy(&out).contains("sk-ant-real"));
    }
}
