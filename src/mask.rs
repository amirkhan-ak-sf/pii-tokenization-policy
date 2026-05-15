//! Format-preserving masking and the per-request `Vault`.
//!
//! The masking algorithm walks the input character by character and
//! replaces each character with one of the same class:
//!
//!   * `a..z`        -> random `a..z`
//!   * `A..Z`        -> random `A..Z`
//!   * `0..9`        -> random `0..9`
//!   * everything else passes through unchanged
//!
//! `DataType` shifts which non-alphanumeric characters get re-randomized
//! vs. preserved (e.g. `Email` keeps `@`, `.`, `-`, `_`).
//!
//! The Vault stores `(mask, original)` pairs in insertion order so the
//! response phase can build a single Aho-Corasick over the masks. It
//! also indexes by original so the same value within one request always
//! gets the same mask — essential for the unmask round trip.
//!
//! Per-request randomness comes from a ChaCha8Rng seeded once at request
//! entry. The seed is built by hashing some entropy with SHA-256, which
//! gives us 32 bytes regardless of input shape and avoids pulling in
//! `rand` or `getrandom` (both require WASM-friendly OS entropy that's
//! awkward inside Envoy WASM).

use std::collections::{HashMap, HashSet};

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use crate::config::DataType;

const COLLISION_RETRIES: usize = 16;

pub struct Vault {
    /// `(mask, original)` in insertion order. The unmask path builds an
    /// Aho-Corasick over the first columns; insertion order matters
    /// because earlier inserts are typically longer / more specific.
    entries: Vec<(String, String)>,
    /// Reverse index: original -> position in `entries`.
    by_original: HashMap<String, usize>,
    /// Set of all masks issued so far, for collision detection.
    seen_masks: HashSet<String>,
    rng: ChaCha8Rng,
    /// Counter used as the suffix for opaque-token fallbacks if FP
    /// generation collides 16 times in a row.
    fallback_counter: u64,
    /// Hard cap from `PolicyConfig::max_vault_entries`. When reached,
    /// `mask_value` returns the original value unchanged (so the caller's
    /// span-based rebuilder skips the substitution) and bumps
    /// `truncations`.
    max_entries: usize,
    pub truncations: u64,
}

impl Vault {
    pub fn new(seed: [u8; 32], max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            by_original: HashMap::new(),
            seen_masks: HashSet::new(),
            rng: ChaCha8Rng::from_seed(seed),
            fallback_counter: 0,
            max_entries,
            truncations: 0,
        }
    }

    pub fn empty() -> Self {
        Self::new([0u8; 32], 0)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterate in insertion order. Used by the unmask side to build its
    /// Aho-Corasick automaton over the masks.
    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }

    /// Mask a value. Idempotent within a single Vault: the same `original`
    /// always yields the same mask (so multiple matches of the same
    /// value, e.g. an SSN that appears twice in a JSON body, get the
    /// same mask and the unmask-side AC still resolves them).
    ///
    /// Returns the original unchanged when `enroll=false` (used for
    /// scope=request rules — the upstream sees the mask but the unmask
    /// side does NOT enroll the pair, so the client also sees the mask).
    /// Returns the original unchanged when the vault is full
    /// (`max_entries` reached).
    pub fn mask_value(&mut self, original: &str, dt: DataType, enroll: bool) -> String {
        if let Some(idx) = self.by_original.get(original) {
            return self.entries[*idx].0.clone();
        }
        if !enroll {
            return generate_fp(original, dt, &mut self.rng);
        }
        if self.entries.len() >= self.max_entries {
            self.truncations += 1;
            return original.to_string();
        }

        let mut mask = String::new();
        let mut accepted = false;
        for _ in 0..COLLISION_RETRIES {
            mask = generate_fp(original, dt, &mut self.rng);
            if mask != original
                && !self.seen_masks.contains(&mask)
                && !self.by_original.contains_key(&mask)
            {
                accepted = true;
                break;
            }
        }
        if !accepted {
            // Rare: the FP space for this length / class is exhausted or
            // the RNG keeps colliding. Emit an opaque fallback. The
            // unmask side handles this transparently because it just
            // does a string replace from the vault.
            self.fallback_counter += 1;
            mask = format!("##MASK_{}_##", self.fallback_counter);
        }

        let idx = self.entries.len();
        self.seen_masks.insert(mask.clone());
        self.entries.push((mask.clone(), original.to_string()));
        self.by_original.insert(original.to_string(), idx);
        mask
    }
}

/// Build a 32-byte seed from arbitrary entropy bytes via SHA-256.
pub fn seed_from(entropy: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(entropy);
    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

/// Generate a format-preserving replacement for `s`, character-by-character.
fn generate_fp(s: &str, dt: DataType, rng: &mut ChaCha8Rng) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(fp_char(c, dt, rng));
    }
    out
}

fn fp_char(c: char, dt: DataType, rng: &mut ChaCha8Rng) -> char {
    match c {
        'a'..='z' => random_lower(rng),
        'A'..='Z' => random_upper(rng),
        '0'..='9' => random_digit(rng),
        '@' | '.' | '-' | '_' if dt == DataType::Email => c,
        '-' | '/' if dt == DataType::Identifier => c,
        // Number: keep all non-digits intact (commas, currency symbols,
        // spaces, decimal points). The digit-only branch already runs
        // above, so the actual digits get re-randomized.
        _ => c,
    }
}

fn random_lower(rng: &mut ChaCha8Rng) -> char {
    let n = (rng.next_u32() % 26) as u8;
    (b'a' + n) as char
}

fn random_upper(rng: &mut ChaCha8Rng) -> char {
    let n = (rng.next_u32() % 26) as u8;
    (b'A' + n) as char
}

fn random_digit(rng: &mut ChaCha8Rng) -> char {
    let n = (rng.next_u32() % 10) as u8;
    (b'0' + n) as char
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> Vault {
        Vault::new(seed_from(b"test-seed"), 1000)
    }

    fn matches_shape(original: &str, masked: &str) -> bool {
        if original.len() != masked.len() {
            return false;
        }
        original
            .chars()
            .zip(masked.chars())
            .all(|(o, m)| match o {
                'a'..='z' => m.is_ascii_lowercase(),
                'A'..='Z' => m.is_ascii_uppercase(),
                '0'..='9' => m.is_ascii_digit(),
                _ => o == m,
            })
    }

    #[test]
    fn name_preserves_shape() {
        let mut v = vault();
        let masked = v.mask_value("Amir Khan", DataType::Name, true);
        assert_ne!(masked, "Amir Khan");
        assert!(matches_shape("Amir Khan", &masked), "got '{masked}'");
        // Space at index 4 stays a space.
        assert_eq!(masked.chars().nth(4), Some(' '));
    }

    #[test]
    fn ssn_preserves_shape() {
        let mut v = vault();
        let masked = v.mask_value("123-45-6789", DataType::Number, true);
        assert_ne!(masked, "123-45-6789");
        let re = regex::Regex::new(r"^\d{3}-\d{2}-\d{4}$").unwrap();
        assert!(re.is_match(&masked), "got '{masked}'");
    }

    #[test]
    fn email_preserves_punctuation() {
        let mut v = vault();
        let masked = v.mask_value("amir.khan@khan.com", DataType::Email, true);
        assert_ne!(masked, "amir.khan@khan.com");
        let re = regex::Regex::new(r"^[a-z]{4}\.[a-z]{4}@[a-z]{4}\.[a-z]{3}$").unwrap();
        assert!(re.is_match(&masked), "got '{masked}'");
    }

    #[test]
    fn same_value_same_mask_within_request() {
        let mut v = vault();
        let m1 = v.mask_value("Amir Khan", DataType::Name, true);
        let m2 = v.mask_value("Amir Khan", DataType::Name, true);
        assert_eq!(m1, m2);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn different_values_different_masks() {
        let mut v = vault();
        let a = v.mask_value("Amir", DataType::Name, true);
        let b = v.mask_value("Bart", DataType::Name, true);
        assert_ne!(a, b);
    }

    #[test]
    fn different_seeds_yield_different_masks() {
        let mut v1 = Vault::new(seed_from(b"seed-one"), 1000);
        let mut v2 = Vault::new(seed_from(b"seed-two"), 1000);
        let m1 = v1.mask_value("Amir Khan", DataType::Name, true);
        let m2 = v2.mask_value("Amir Khan", DataType::Name, true);
        assert_ne!(m1, m2, "different seeds should not collide on a 9-char input");
    }

    #[test]
    fn enroll_false_skips_vault() {
        let mut v = vault();
        let m = v.mask_value("Amir Khan", DataType::Name, false);
        assert_ne!(m, "Amir Khan");
        assert!(v.is_empty());
    }

    #[test]
    fn truncates_when_full() {
        let mut v = Vault::new(seed_from(b"x"), 2);
        let _ = v.mask_value("alpha", DataType::Name, true);
        let _ = v.mask_value("bravo", DataType::Name, true);
        let m = v.mask_value("charlie", DataType::Name, true);
        assert_eq!(m, "charlie", "third entry should pass through");
        assert_eq!(v.truncations, 1);
    }
}
