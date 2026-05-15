//! Response-phase unmask. Builds a single Aho-Corasick over the masks
//! recorded in the request's Vault and replaces each match with the
//! original. Single linear pass over the response body.

use aho_corasick::{AhoCorasickBuilder, MatchKind};

use crate::mask::Vault;

pub fn unmask_text(input: &str, vault: &Vault) -> String {
    if input.is_empty() || vault.is_empty() {
        return input.to_string();
    }

    let entries = vault.entries();
    let masks: Vec<&str> = entries.iter().map(|(m, _)| m.as_str()).collect();

    let ac = match AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .ascii_case_insensitive(false)
        .build(&masks)
    {
        Ok(ac) => ac,
        Err(_) => return input.to_string(),
    };

    let mut out = String::with_capacity(input.len());
    let mut last_end = 0usize;
    for m in ac.find_iter(input) {
        out.push_str(&input[last_end..m.start()]);
        let original = entries[m.pattern().as_usize()].1.as_str();
        out.push_str(original);
        last_end = m.end();
    }
    out.push_str(&input[last_end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DataType;
    use crate::mask::seed_from;

    #[test]
    fn round_trip_single() {
        let mut v = Vault::new(seed_from(b"x"), 100);
        let mask = v.mask_value("Amir Khan", DataType::Name, true);
        let body = format!("Hello, {mask}!");
        let restored = unmask_text(&body, &v);
        assert_eq!(restored, "Hello, Amir Khan!");
    }

    #[test]
    fn round_trip_multiple_overlapping_lengths() {
        let mut v = Vault::new(seed_from(b"x"), 100);
        let m1 = v.mask_value("Amir Khan", DataType::Name, true);
        let m2 = v.mask_value("Amir", DataType::Name, true);
        // The longer mask must match before the shorter one — leftmost-
        // longest in AC handles that.
        let body = format!("{m2} {m1} {m2}");
        let restored = unmask_text(&body, &v);
        assert_eq!(restored, "Amir Amir Khan Amir");
    }

    #[test]
    fn empty_vault_passes_through() {
        let v = Vault::empty();
        assert_eq!(unmask_text("hello", &v), "hello");
    }

    #[test]
    fn body_without_masks_is_unchanged() {
        let mut v = Vault::new(seed_from(b"x"), 100);
        let _ = v.mask_value("Amir Khan", DataType::Name, true);
        assert_eq!(unmask_text("nothing to see here", &v), "nothing to see here");
    }
}
