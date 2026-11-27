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
//! Inside that head the substitution is scoped to where a credential
//! belongs: the `Authorization` and `x-api-key` header values, and the
//! query parameters the binding names (`--secret KEY=host?param`). A
//! placeholder anywhere else -- the path, another header -- refuses the
//! request, because a server that reflects that place (a redirect, a 404
//! page, CORS's `Access-Control-Allow-Origin`) would hand the real value
//! back to the sandbox. The response head is scrubbed of the real value
//! on its way back, as defence in depth.
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
    /// Query parameters whose values may carry the placeholder, from the
    /// `?param,param` suffix of the `--secret` value. Empty by default:
    /// no query parameter is a credential unless the binding says so.
    pub query_params: Vec<String>,
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
            query_params: Vec::new(),
        }
    }

    /// The same binding, also allowed in the query parameters `params`.
    pub(crate) fn with_query_params(mut self, params: Vec<String>) -> Self {
        self.query_params = params;
        self
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
            .field("query_params", &self.query_params)
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

/// The hosts and the query parameters a `secret_hosts` value names:
/// `host[,host...][?param[,param...]]`. The parameter list applies to
/// every host of the value. A value without `?` names no parameter, which
/// is every value written before parameters existed.
pub(crate) fn split_spec(value: &str) -> (Vec<String>, Vec<String>) {
    match value.split_once('?') {
        Some((hosts, params)) => (split_hosts(hosts), split_hosts(params)),
        None => (split_hosts(value), Vec::new()),
    }
}

/// Whether `name` can be a query parameter a binding names: a non-empty
/// run of ASCII letters, digits, `_`, `-` and `.`, so it never needs
/// percent-decoding to be compared.
pub(crate) fn valid_query_param(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

/// The request was refused: a placeholder sat outside the places its
/// binding allows, and substituting it there could reflect the real value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OutOfScope;

/// Headers whose value is a credential, and the only ones substituted.
const CREDENTIAL_HEADERS: [&[u8]; 2] = [b"authorization", b"x-api-key"];

/// Substitute each binding's placeholder in `head` (the request line and
/// headers only -- never the body) where a credential belongs: the
/// [`CREDENTIAL_HEADERS`] values (Basic auth decoded and re-encoded) and
/// the values of the query parameters the binding names (the real value
/// percent-encoded). Returns the rewritten head and the substitution
/// count for auditing, or [`OutOfScope`] when a placeholder remains
/// anywhere else. A placeholder that never appears costs nothing.
pub(crate) fn rewrite_head(
    head: &[u8],
    bindings: &[SecretBinding],
) -> Result<(Vec<u8>, usize), OutOfScope> {
    let mut out = Vec::with_capacity(head.len());
    let mut substitutions = 0;
    let mut rest = head;
    let mut first = true;
    loop {
        let line_end = find_subslice(rest, b"\r\n").unwrap_or(rest.len());
        let line = &rest[..line_end];
        let rewritten = if first {
            rewrite_request_line(line, bindings, &mut substitutions)
        } else {
            rewrite_header_line(line, bindings, &mut substitutions)
        };
        out.extend_from_slice(&rewritten);
        first = false;
        if line_end == rest.len() {
            break;
        }
        out.extend_from_slice(b"\r\n");
        rest = &rest[line_end + 2..];
    }
    let leftover = bindings.iter().any(|binding| {
        find_subslice(&out, binding.placeholder.as_bytes()).is_some()
    });
    if leftover {
        return Err(OutOfScope);
    }
    Ok((out, substitutions))
}

/// Replace each binding's real value in a response head with its
/// placeholder, raw and percent-encoded: a server that echoes the
/// credential (a `Location` carrying the query, a debug header) must not
/// hand it to the sandbox. Only the head is passed here; the body's
/// length is the server's to state.
pub(crate) fn scrub_response_head(
    head: &[u8],
    bindings: &[SecretBinding],
) -> Vec<u8> {
    let mut out = head.to_vec();
    for binding in bindings {
        if binding.real.is_empty() {
            continue;
        }
        let encoded = percent_encode(binding.real.as_bytes());
        for real in [binding.real.as_bytes(), encoded.as_slice()] {
            out = replace_all(&out, real, binding.placeholder.as_bytes()).0;
        }
    }
    out
}

/// The request line `METHOD SP target SP version`: only the values of
/// the query parameters a binding names are substituted.
fn rewrite_request_line(
    line: &[u8],
    bindings: &[SecretBinding],
    substitutions: &mut usize,
) -> Vec<u8> {
    let mut parts = line.splitn(3, |b| *b == b' ');
    let (Some(method), Some(target), Some(version)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return line.to_vec();
    };
    let Some(query_at) = target.iter().position(|b| *b == b'?') else {
        return line.to_vec();
    };
    let (path, query) = (&target[..=query_at], &target[query_at + 1..]);
    let mut rebuilt_query = Vec::with_capacity(query.len());
    for (index, pair) in query.split(|b| *b == b'&').enumerate() {
        if index > 0 {
            rebuilt_query.push(b'&');
        }
        let Some(eq) = pair.iter().position(|b| *b == b'=') else {
            rebuilt_query.extend_from_slice(pair);
            continue;
        };
        let (name, value) = (&pair[..eq], &pair[eq + 1..]);
        let mut value = value.to_vec();
        for binding in bindings {
            if binding.query_params.iter().any(|p| p.as_bytes() == name) {
                let (rewritten, n) = replace_all(
                    &value,
                    binding.placeholder.as_bytes(),
                    &percent_encode(binding.real.as_bytes()),
                );
                value = rewritten;
                *substitutions += n;
            }
        }
        rebuilt_query.extend_from_slice(name);
        rebuilt_query.push(b'=');
        rebuilt_query.extend_from_slice(&value);
    }
    let mut out = method.to_vec();
    out.push(b' ');
    out.extend_from_slice(path);
    out.extend_from_slice(&rebuilt_query);
    out.push(b' ');
    out.extend_from_slice(version);
    out
}

/// A header line: substituted only when its name is one of the
/// [`CREDENTIAL_HEADERS`], and then only in its value.
fn rewrite_header_line(
    line: &[u8],
    bindings: &[SecretBinding],
    substitutions: &mut usize,
) -> Vec<u8> {
    let Some(colon) = line.iter().position(|b| *b == b':') else {
        return line.to_vec();
    };
    let name = &line[..colon];
    if !CREDENTIAL_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
    {
        return line.to_vec();
    }
    let line = rewrite_basic_line(line, bindings, substitutions);
    let colon = line.iter().position(|b| *b == b':').unwrap_or(line.len());
    let mut value = line[colon..].to_vec();
    for binding in bindings {
        let (rewritten, n) = replace_all(
            &value,
            binding.placeholder.as_bytes(),
            binding.real.as_bytes(),
        );
        value = rewritten;
        *substitutions += n;
    }
    let mut out = line[..colon].to_vec();
    out.extend_from_slice(&value);
    out
}

/// RFC 3986 percent-encoding of everything outside the unreserved set,
/// so a real value with `&`, `=`, `+` or `/` stays one query value.
fn percent_encode(input: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(&[
                b'%',
                HEX[usize::from(b >> 4)],
                HEX[usize::from(b & 15)],
            ]);
        }
    }
    out
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
    let is_auth = name.eq_ignore_ascii_case(b"authorization");
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
        let (out, count) = rewrite_head(head.as_bytes(), &[binding()]).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(count, 2);
        assert!(!out.contains(&b.placeholder));
        assert_eq!(out.matches("sk-ant-real").count(), 2);
    }

    #[test]
    fn rewrite_head_noop_without_placeholder() {
        let head = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";
        let (out, count) = rewrite_head(head, &[binding()]).unwrap();
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
        let (out, count) = rewrite_head(head.as_bytes(), &[binding()]).unwrap();
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
        let (out, count) = rewrite_head(head, &[binding()]).unwrap();
        assert_eq!(count, 0);
        assert_eq!(out, head);
    }

    #[test]
    fn rewrite_head_treats_head_as_bytes() {
        // A placeholder straddling a multibyte boundary still matches;
        // non-UTF-8 bytes elsewhere pass through untouched.
        let b = binding();
        let mut head = b"GET / HTTP/1.1\r\nx-api-key: ".to_vec();
        head.extend_from_slice(&[0xff, 0xfe]);
        head.extend_from_slice(b.placeholder.as_bytes());
        head.extend_from_slice(b"\r\n\r\n");
        let (out, count) = rewrite_head(&head, &[binding()]).unwrap();
        assert_eq!(count, 1);
        assert!(out.windows(2).any(|w| w == [0xff, 0xfe]));
        assert!(String::from_utf8_lossy(&out).contains("sk-ant-real"));
    }

    #[test]
    fn a_placeholder_outside_a_credential_place_refuses_the_request() {
        // Each of these places is one a server may reflect back.
        let b = binding();
        let p = &b.placeholder;
        for head in [
            format!("GET /{p}/ HTTP/1.1\r\nhost: a.example\r\n\r\n"),
            format!("GET /?q={p} HTTP/1.1\r\nhost: a.example\r\n\r\n"),
            format!("GET / HTTP/1.1\r\norigin: https://{p}.x\r\n\r\n"),
            format!(
                "GET / HTTP/1.1\r\nproxy-authorization: Bearer {p}\r\n\r\n"
            ),
            format!("GET / HTTP/1.1\r\nx-api-key: {p}\r\nx-echo: {p}\r\n\r\n"),
        ] {
            assert_eq!(
                rewrite_head(head.as_bytes(), &[binding()]),
                Err(OutOfScope),
                "{head}"
            );
        }
    }

    #[test]
    fn a_named_query_parameter_carries_the_value_percent_encoded() {
        let b = SecretBinding::new("MAPS_KEY", "a&b=c/d+e", "maps.example")
            .with_query_params(vec!["key".into()]);
        let head = format!(
            "GET /geo?x=1&key={}&y=2 HTTP/1.1\r\nhost: maps.example\r\n\r\n",
            b.placeholder
        );
        let (out, count) =
            rewrite_head(head.as_bytes(), std::slice::from_ref(&b)).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET /geo?x=1&key=a%26b%3Dc%2Fd%2Be&y=2 HTTP/1.1\r\nhost: maps.example\r\n\r\n"
        );
        // Another parameter, even on the same binding, is not a credential.
        let other = format!(
            "GET /geo?q={} HTTP/1.1\r\nhost: maps.example\r\n\r\n",
            b.placeholder
        );
        assert_eq!(
            rewrite_head(other.as_bytes(), std::slice::from_ref(&b)),
            Err(OutOfScope)
        );
    }

    #[test]
    fn the_response_head_loses_the_real_value() {
        let b = SecretBinding::new("K", "s3cr&t", "a.example");
        let head = b"HTTP/1.1 302 Found\r\nlocation: /x?key=s3cr%26t\r\nx-debug: s3cr&t\r\n\r\n";
        let out = String::from_utf8(scrub_response_head(
            head,
            std::slice::from_ref(&b),
        ))
        .unwrap();
        assert!(!out.contains("s3cr"), "{out}");
        assert_eq!(out.matches(&b.placeholder).count(), 2);
    }

    #[test]
    fn a_secret_value_names_hosts_then_query_parameters() {
        assert_eq!(
            split_spec("a.example,b.example?key,api_key"),
            (
                vec!["a.example".to_string(), "b.example".to_string()],
                vec!["key".to_string(), "api_key".to_string()]
            )
        );
        assert_eq!(split_spec("a.example"), (vec!["a.example".into()], vec![]));
        assert!(valid_query_param("api_key.v-2"));
        for bad in ["", "a b", "a=b", "a&b", "k%20"] {
            assert!(!valid_query_param(bad), "{bad:?}");
        }
    }
}
