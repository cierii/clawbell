//! Bounded session vault and streaming DLP. Input is withheld until a complete
//! inspection unit is available, including secrets crossing chunk boundaries.
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use regex::Regex;
use secrecy::{ExposeSecret, SecretBox};
use std::fmt::Write;
use zeroize::Zeroizing;
const PREFIX: &str = "[clawbell:";
/// Static denial without sensitive diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("dlp_denied")]
pub struct Denied;
struct Entry {
    token: String,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}
/// Encrypted RAM vault for exactly one session and upstream. No serialization,
/// Debug or cloning. Process compromise and swapping are outside its guarantee.
pub struct Vault {
    key: SecretBox<[u8; 32]>,
    entries: Vec<Entry>,
    patterns: Vec<Regex>,
    max_bytes: usize,
    stored_bytes: usize,
}
impl Vault {
    /// Fresh OS-random key; bounds each unit and total stored plaintext.
    /// # Errors
    /// Denies invalid limits, entropy or pattern compilation failure.
    pub fn new(max_bytes: usize) -> Result<Self, Denied> {
        if max_bytes == 0 || max_bytes > 16 * 1024 * 1024 {
            return Err(Denied);
        }
        let mut key = Box::new([0; 32]);
        getrandom::getrandom(key.as_mut()).map_err(|_| Denied)?;
        let patterns = [
            r"(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----",
            r#"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|mssql)://[^\s\"'<>]+"#,
            r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{16,})",
            r#"(?im)(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_]*\s*[=:]\s*)(?:\"([^\"\r\n]+)\"|'([^'\r\n]+)'|([^\s#\r\n]+))"#,
            r"(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-[A-Za-z0-9-]+) [A-Za-z0-9+/=]+",
        ].into_iter().map(Regex::new).collect::<Result<Vec<_>, _>>().map_err(|_| Denied)?;
        Ok(Self {
            key: SecretBox::new(key),
            entries: Vec::new(),
            patterns,
            max_bytes,
            stored_bytes: 0,
        })
    }
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.key.expose_secret().into())
    }
    fn plaintext(&self, entry: &Entry) -> Result<Zeroizing<Vec<u8>>, Denied> {
        self.cipher()
            .decrypt(XNonce::from_slice(&entry.nonce), entry.ciphertext.as_ref())
            .map(Zeroizing::new)
            .map_err(|_| Denied)
    }
    /// Register an exact secret, returning a session-stable random opaque token.
    /// # Errors
    /// Denies empty values, reserved markers, exhaustion and crypto failures.
    pub fn register(&mut self, secret: &str) -> Result<String, Denied> {
        if secret.is_empty() || secret.contains(PREFIX) {
            return Err(Denied);
        }
        for entry in &self.entries {
            if self.plaintext(entry)?.as_slice() == secret.as_bytes() {
                return Ok(entry.token.clone());
            }
        }
        if self.entries.len() >= 128
            || secret.len() > self.max_bytes.saturating_sub(self.stored_bytes)
        {
            return Err(Denied);
        }
        let mut nonce = [0; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| Denied)?;
        let mut token = PREFIX.to_owned();
        for byte in nonce {
            write!(&mut token, "{byte:02x}").map_err(|_| Denied)?;
        }
        token.push(']');
        let ciphertext = self
            .cipher()
            .encrypt(XNonce::from_slice(&nonce), secret.as_bytes())
            .map_err(|_| Denied)?;
        self.stored_bytes += secret.len();
        self.entries.push(Entry {
            token: token.clone(),
            nonce,
            ciphertext,
        });
        Ok(token)
    }
    /// Redact complete UTF-8 text. Rejects forged markers and incomplete PEM.
    /// # Errors
    /// Denies oversized, ambiguous units or exhausted vault capacity.
    pub fn redact(&mut self, text: &str) -> Result<String, Denied> {
        if text.len() > self.max_bytes || text.contains(PREFIX) {
            return Err(Denied);
        }
        let mut spans = Vec::new();
        for pattern in &self.patterns {
            for captures in pattern.captures_iter(text) {
                let found = (1..captures.len())
                    .find_map(|i| captures.get(i))
                    .or_else(|| captures.get(0))
                    .ok_or(Denied)?;
                spans.push((found.start(), found.end()));
            }
        }
        for entry in &self.entries {
            let plain = self.plaintext(entry)?;
            let secret = std::str::from_utf8(&plain).map_err(|_| Denied)?;
            spans.extend(
                text.match_indices(secret)
                    .map(|(start, s)| (start, start + s.len())),
            );
        }
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in spans {
            if let Some(last) = merged.last_mut()
                && start < last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        let mut result = String::new();
        let mut cursor = 0;
        for (start, end) in merged {
            result.push_str(&text[cursor..start]);
            result.push_str(&self.register(&text[start..end])?);
            cursor = end;
        }
        result.push_str(&text[cursor..]);
        if result.contains("-----BEGIN ") || result.len() > self.max_bytes {
            return Err(Denied);
        }
        Ok(result)
    }
    /// Inspect an ordered text unit before any fragment is released. Full known
    /// secrets crossing field boundaries refuse rather than rewriting semantics.
    /// A trailing proper prefix also refuses: it could be completed by a later
    /// response. This is deliberately conservative, even for one-character tails.
    /// # Errors
    /// Refuses split secrets, incomplete known-secret prefixes or unit overflow.
    pub fn inspect_fragments(&mut self, fragments: &[&str]) -> Result<(), Denied> {
        let mut text = Zeroizing::new(String::new());
        let mut boundaries = Vec::new();
        for fragment in fragments {
            if fragment.len() > self.max_bytes.saturating_sub(text.len()) {
                return Err(Denied);
            }
            text.push_str(fragment);
            boundaries.push(text.len());
        }
        // Learn patterns spanning blocks before checking exact known values.
        // The resulting markers are never used as catalog/policy input.
        self.redact(&text)?;
        for entry in &self.entries {
            let plain = self.plaintext(entry)?;
            let secret = std::str::from_utf8(&plain).map_err(|_| Denied)?;
            inspect_known_fragments(text.as_bytes(), secret.as_bytes(), &boundaries)?;
        }
        Ok(())
    }
    /// Reject raw secrets mixed with references; validate every reference.
    /// # Errors
    /// Denies unknown references and detectable raw credentials.
    pub fn check_request(&mut self, text: &str) -> Result<(), Denied> {
        let mut plain = String::new();
        let mut rest = text;
        while let Some(start) = rest.find(PREFIX) {
            plain.push_str(&rest[..start]);
            let end = rest[start..].find(']').ok_or(Denied)? + start + 1;
            self.restore(&rest[start..end])?;
            rest = &rest[end..];
        }
        plain.push_str(rest);
        if self.redact(&plain)? != plain {
            return Err(Denied);
        }
        Ok(())
    }
    /// Resolve tokens only after destination-specific authorization.
    /// # Errors
    /// Denies unknown tokens, invalid ciphertext and expanded size overflow.
    pub fn restore(&self, text: &str) -> Result<Zeroizing<String>, Denied> {
        let mut result = Zeroizing::new(String::new());
        let mut rest = text;
        while let Some(start) = rest.find(PREFIX) {
            result.push_str(&rest[..start]);
            let end = rest[start..].find(']').ok_or(Denied)? + start + 1;
            let entry = self
                .entries
                .iter()
                .find(|e| e.token == rest[start..end])
                .ok_or(Denied)?;
            let plain = self.plaintext(entry)?;
            result.push_str(std::str::from_utf8(&plain).map_err(|_| Denied)?);
            rest = &rest[end..];
            if result.len() > self.max_bytes {
                return Err(Denied);
            }
        }
        result.push_str(rest);
        if result.len() > self.max_bytes {
            return Err(Denied);
        }
        Ok(result)
    }
}
/// Linear prefix matching also finds overlapping occurrences (e.g. `aaa` in
/// `aaaa`). A complete final occurrence is safe only inside one redacted field;
/// otherwise a surviving proper prefix must never reach the next response.
fn inspect_known_fragments(text: &[u8], secret: &[u8], boundaries: &[usize]) -> Result<(), Denied> {
    let mut prefixes = vec![0; secret.len()];
    let mut matched = 0;
    for index in 1..secret.len() {
        while matched > 0 && secret[matched] != secret[index] {
            matched = prefixes[matched - 1];
        }
        if secret[matched] == secret[index] {
            matched += 1;
        }
        prefixes[index] = matched;
    }
    matched = 0;
    let mut complete_at_end = false;
    let mut next_redacted_start = 0;
    let mut boundary = 0;
    for (index, byte) in text.iter().enumerate() {
        while matched > 0 && secret[matched] != *byte {
            matched = prefixes[matched - 1];
        }
        if secret[matched] == *byte {
            matched += 1;
        }
        if matched == secret.len() {
            let end = index + 1;
            let start = end - secret.len();
            while boundaries
                .get(boundary)
                .is_some_and(|boundary| *boundary <= start)
            {
                boundary += 1;
            }
            if boundaries
                .get(boundary)
                .is_some_and(|boundary| *boundary < end)
            {
                return Err(Denied);
            }
            // Match the field redactor's non-overlapping exact replacements.
            // An overlapping final match may leave a plaintext suffix behind.
            if start >= next_redacted_start {
                complete_at_end = end == text.len();
                next_redacted_start = end;
            }
            matched = prefixes[matched - 1];
        }
    }
    if !complete_at_end && matched > 0 {
        return Err(Denied);
    }
    Ok(())
}
/// Incremental byte buffer, wiped on drop; releases no uninspected prefix.
pub struct Scanner {
    buffer: Zeroizing<Vec<u8>>,
    limit: usize,
    failed: bool,
}
impl Scanner {
    /// Create a scanner with a byte limit.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            buffer: Zeroizing::new(Vec::new()),
            limit,
            failed: false,
        }
    }
    /// Append a fragment, including partial UTF-8.
    /// # Errors
    /// Overflow permanently poisons this unit.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), Denied> {
        if self.failed || chunk.len() > self.limit.saturating_sub(self.buffer.len()) {
            self.failed = true;
            return Err(Denied);
        }
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }
    /// Finish the unit and release redacted text.
    /// # Errors
    /// Denies invalid UTF-8, overflow or inspection failure.
    pub fn finish(self, vault: &mut Vault) -> Result<String, Denied> {
        if self.failed {
            return Err(Denied);
        }
        vault.redact(std::str::from_utf8(&self.buffer).map_err(|_| Denied)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binary_word(value: usize, length: usize) -> String {
        (0..length)
            .map(|bit| if value & (1 << bit) == 0 { 'a' } else { 'b' })
            .collect()
    }
    #[test]
    fn exhaustive_overlaps_never_release_secret_or_completable_suffix() {
        for secret_len in 1..=4 {
            for pattern in 0..(1 << secret_len) {
                let secret = binary_word(pattern, secret_len);
                for length in 0..=7 {
                    for word in 0..(1 << length) {
                        let text = binary_word(word, length);
                        for split in 0..=length {
                            if inspect_known_fragments(
                                text.as_bytes(),
                                secret.as_bytes(),
                                &[split, length],
                            )
                            .is_ok()
                            {
                                let redacted = format!(
                                    "{}{}",
                                    text[..split].replace(&secret, "MARKER"),
                                    text[split..].replace(&secret, "MARKER")
                                );
                                assert!(!redacted.contains(&secret));
                                for prefix in 1..secret_len {
                                    assert!(!redacted.ends_with(&secret[..prefix]));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
