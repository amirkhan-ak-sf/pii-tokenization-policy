//! Built-in pattern catalog.
//!
//! `registry()` returns a static slice of `(name, regex)` pairs. The
//! `name` is the value the operator picks from the GCL `builtinPattern`
//! enum dropdown (e.g. `"GovernmentId/GermanSvnr"`). The `regex` is the
//! pattern that gets compiled with the `regex` crate at policy load.
//!
//! Categories are reflected in the name prefix, so the dropdown groups
//! visually by category when sorted alphabetically.
//!
//! Notes on the patterns:
//! - We use `\b` word boundaries where it matters. Some patterns (e.g.
//!   IPv6, URLs) cannot rely on `\b` and use anchored character classes.
//! - We do NOT validate checksums (Luhn for credit-card / SIN, IBAN
//!   mod-97, BSN 11-test, etc.). Validation is the upstream's job; the
//!   gateway only needs *reasonable shape* matching to mask.
//! - Some patterns are intentionally slightly broad (e.g. UnixSeconds
//!   matches any 10-digit number starting with 1) — false positives are
//!   acceptable for masking; false negatives are not.

/// Full catalog as a static slice. Currently unused outside the test
/// module; kept available for future tooling (e.g. dumping the catalog
/// to a documentation file).
#[allow(dead_code)]
pub fn registry() -> &'static [(&'static str, &'static str)] {
    PATTERNS
}

/// Look up a built-in pattern by name. Returns the regex string.
pub fn lookup(name: &str) -> Option<&'static str> {
    PATTERNS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, r)| *r)
}

/// All catalog entries. Keep alphabetical by name so the GCL dropdown is
/// sorted consistently.
const PATTERNS: &[(&str, &str)] = &[
    // ---- Contact ----------------------------------------------------------
    (
        "Contact/Email",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    ),
    // Generic phone: international or local, 7-15 digits with separators.
    (
        "Contact/PhoneGeneric",
        r"\+?\d[\d\-\s().]{6,18}\d",
    ),

    // ---- Crypto -----------------------------------------------------------
    (
        "Crypto/Btc",
        r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b",
    ),
    (
        "Crypto/EthereumAddress",
        r"\b0x[a-fA-F0-9]{40}\b",
    ),

    // ---- Currency ---------------------------------------------------------
    (
        "Currency/Eur",
        r"(?:€\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?|\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?\s?€)",
    ),
    (
        "Currency/Gbp",
        r"£\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
    ),
    (
        "Currency/Iso4217Code",
        r"\b(?:USD|EUR|GBP|JPY|CHF|CAD|AUD|CNY|INR|BRL|MXN|KRW|SEK|NOK|DKK|PLN|RUB|TRY|ZAR|SGD|HKD|NZD)\b",
    ),
    (
        "Currency/Usd",
        r"\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
    ),

    // ---- Date / Time ------------------------------------------------------
    (
        "DateTime/EuDate",
        r"\b(?:0[1-9]|[12]\d|3[01])[./](?:0[1-9]|1[0-2])[./](?:19|20)\d{2}\b",
    ),
    (
        "DateTime/Iso8601Date",
        r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b",
    ),
    (
        "DateTime/Iso8601DateTime",
        r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?\b",
    ),
    (
        "DateTime/Rfc2822",
        r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}",
    ),
    (
        "DateTime/Time24h",
        r"\b(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\b",
    ),
    (
        "DateTime/UnixMillis",
        r"\b1\d{12}\b",
    ),
    (
        "DateTime/UnixSeconds",
        r"\b1\d{9}\b",
    ),
    (
        "DateTime/UsDate",
        r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b",
    ),

    // ---- Financial --------------------------------------------------------
    (
        "Financial/CreditCard",
        // 13-19 digits, optional separators every 4. Not Luhn-validated.
        r"\b(?:\d[ -]?){12,18}\d\b",
    ),
    (
        "Financial/Cusip",
        r"\b[0-9A-Z]{9}\b",
    ),
    (
        "Financial/Iban",
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    ),
    (
        "Financial/Isin",
        r"\b[A-Z]{2}[A-Z0-9]{9}\d\b",
    ),
    (
        "Financial/SwiftBic",
        r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
    ),
    (
        "Financial/UsAbaRouting",
        r"\b\d{9}\b",
    ),

    // ---- Geographic -------------------------------------------------------
    (
        "Geographic/CanadianPostal",
        r"\b[ABCEGHJ-NPRSTVXY]\d[A-Z][ -]?\d[A-Z]\d\b",
    ),
    (
        "Geographic/DutchPostcode",
        r"\b\d{4}\s?[A-Z]{2}\b",
    ),
    (
        "Geographic/FrenchPostcode",
        r"\b\d{5}\b",
    ),
    (
        "Geographic/GermanPlz",
        r"\b\d{5}\b",
    ),
    (
        "Geographic/Iso3166Alpha2",
        r"\b[A-Z]{2}\b",
    ),
    (
        "Geographic/Iso3166Alpha3",
        r"\b[A-Z]{3}\b",
    ),
    (
        "Geographic/ItalianCap",
        r"\b\d{5}\b",
    ),
    (
        "Geographic/LatLng",
        r"[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?),\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)",
    ),
    (
        "Geographic/Mgrs",
        r"\b\d{1,2}[C-X][A-HJ-NP-Z]{2}\d{2,10}\b",
    ),
    (
        "Geographic/PlusCode",
        r"\b[2-9CFGHJMPQRVWX]{2,8}\+[2-9CFGHJMPQRVWX]{2,3}\b",
    ),
    (
        "Geographic/UkPostcode",
        r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b",
    ),
    (
        "Geographic/UsZip",
        r"\b\d{5}(?:-\d{4})?\b",
    ),
    (
        "Geographic/What3Words",
        r"/{0,3}[a-z]+\.[a-z]+\.[a-z]+",
    ),

    // ---- Government IDs ---------------------------------------------------
    (
        "GovernmentId/AustralianMedicare",
        r"\b[2-6]\d{3}\s?\d{5}\s?\d(?:\s?\d)?\b",
    ),
    (
        "GovernmentId/AustralianTfn",
        r"\b\d{3}\s?\d{3}\s?\d{3}\b",
    ),
    (
        // Austria SVNR: 10 digits, the leading 4 are usually the date.
        "GovernmentId/AustrianSvnr",
        r"\b\d{10}\b",
    ),
    (
        "GovernmentId/BrazilianCnpj",
        r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b",
    ),
    (
        "GovernmentId/BrazilianCpf",
        r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",
    ),
    (
        "GovernmentId/CanadianSin",
        r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b",
    ),
    (
        "GovernmentId/DutchBsn",
        r"\b\d{9}\b",
    ),
    (
        "GovernmentId/FrenchInsee",
        // 1 or 2 + 2-digit year + 2-digit month + 2-digit dept (or "2A"/"2B")
        // + 3-digit commune + 3-digit serial + optional 2-digit key.
        r"\b[12]\d{2}(?:0[1-9]|1[0-2]|2\d|3\d|4\d)(?:\d{2}|2[AB])\d{3}\d{3}(?:\d{2})?\b",
    ),
    (
        // 12 chars: YY MM DD A NNNN (Y = check letter)
        "GovernmentId/GermanSvnr",
        r"\b\d{2}\d{6}[A-Z]\d{3}\b",
    ),
    (
        "GovernmentId/IndianAadhaar",
        r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    ),
    (
        "GovernmentId/IndianPan",
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
    ),
    (
        "GovernmentId/ItalianCodiceFiscale",
        r"\b[A-Z]{6}\d{2}[A-EHLMPR-T][0-9LMNP-V]{2}[A-Z][0-9LMNP-V]{3}[A-Z]\b",
    ),
    (
        "GovernmentId/JapaneseMyNumber",
        r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    ),
    (
        "GovernmentId/PolishPesel",
        r"\b\d{11}\b",
    ),
    (
        "GovernmentId/SouthKoreanRrn",
        r"\b\d{6}-?[1-4]\d{6}\b",
    ),
    (
        "GovernmentId/SpanishDniNie",
        r"\b[XYZ]?\d{7,8}[A-HJ-NP-TV-Z]\b",
    ),
    (
        "GovernmentId/SwissAhv",
        r"756\.\d{4}\.\d{4}\.\d{2}",
    ),
    (
        "GovernmentId/UkNino",
        r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b",
    ),
    (
        "GovernmentId/UsSsn",
        r"\b\d{3}-\d{2}-\d{4}\b",
    ),

    // ---- Hashes -----------------------------------------------------------
    (
        // Generic >=20 chars base64. Note: this can match a lot; usually
        // pair with JSON-aware mode and target specific fields.
        "Hash/Base64Generic",
        r"\b[A-Za-z0-9+/]{20,}={0,2}\b",
    ),
    (
        "Hash/Bcrypt",
        r"\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}",
    ),
    (
        "Hash/Md5",
        r"\b[a-f0-9]{32}\b",
    ),
    (
        "Hash/Sha1",
        r"\b[a-f0-9]{40}\b",
    ),
    (
        "Hash/Sha256",
        r"\b[a-f0-9]{64}\b",
    ),
    (
        "Hash/Sha512",
        r"\b[a-f0-9]{128}\b",
    ),

    // ---- Identifiers ------------------------------------------------------
    (
        "Identifier/DiscordUserId",
        r"\b\d{17,19}\b",
    ),
    (
        "Identifier/MongoObjectId",
        r"\b[a-f0-9]{24}\b",
    ),
    (
        "Identifier/NanoId",
        r"\b[A-Za-z0-9_-]{21}\b",
    ),
    (
        "Identifier/Snowflake",
        r"\b\d{17,19}\b",
    ),
    (
        "Identifier/SpotifyTrackId",
        r"\b[0-9A-Za-z]{22}\b",
    ),
    (
        "Identifier/TwitterStatusId",
        r"\b\d{18,19}\b",
    ),
    (
        "Identifier/Ulid",
        r"\b[0-9A-HJKMNP-TV-Z]{26}\b",
    ),
    (
        "Identifier/Uuid",
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    ),
    (
        "Identifier/YouTubeVideoId",
        r"\b[A-Za-z0-9_-]{11}\b",
    ),

    // ---- Media / Files ----------------------------------------------------
    (
        "Media/ColorHex",
        r"#(?:[0-9a-fA-F]{3}){1,2}\b",
    ),
    (
        "Media/ColorRgb",
        r"rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(?:,\s*(?:0|1|0?\.\d+))?\s*\)",
    ),
    (
        "Media/FileExtension",
        r"\.[a-zA-Z0-9]{1,5}\b",
    ),
    (
        "Media/MimeType",
        r"\b(?:application|audio|font|image|model|multipart|text|video)/[a-zA-Z0-9.+-]+\b",
    ),
    (
        "Media/UnixPath",
        r"(?:/[^/\s]+)+/?",
    ),
    (
        "Media/WindowsPath",
        r#"\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*"#,
    ),

    // ---- Misc -------------------------------------------------------------
    (
        "Misc/Icd10Code",
        r"\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b",
    ),
    (
        "Misc/UsLicensePlate",
        r"\b[A-Z0-9]{2,3}[-\s]?[A-Z0-9]{3,4}\b",
    ),
    (
        "Misc/UsVin",
        r"\b[A-HJ-NPR-Z0-9]{17}\b",
    ),

    // ---- Network ----------------------------------------------------------
    (
        "Network/Domain",
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    ),
    (
        "Network/Ipv4",
        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b",
    ),
    (
        // Loose IPv6: any 2..7 colon-separated groups of 1..4 hex digits,
        // optionally with a `::` shortener. Not RFC-strict; sufficient for
        // masking.
        "Network/Ipv6",
        r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b",
    ),
    (
        "Network/Mac",
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
    ),
    (
        "Network/Url",
        r"https?://[^\s/$.?#][^\s]*",
    ),

    // ---- Numbers ----------------------------------------------------------
    (
        "Number/Binary",
        r"\b0[bB][01]+\b",
    ),
    (
        "Number/Hex",
        r"\b0[xX][0-9a-fA-F]+\b",
    ),
    (
        "Number/Percentage",
        r"\b\d{1,3}(?:\.\d+)?%",
    ),
    (
        "Number/Scientific",
        r"\b-?\d+(?:\.\d+)?[eE][+-]?\d+\b",
    ),

    // ---- Products / Publications ------------------------------------------
    (
        "Product/ArxivId",
        r"\b\d{4}\.\d{4,5}(?:v\d+)?\b",
    ),
    (
        "Product/Asin",
        r"\b[A-Z0-9]{10}\b",
    ),
    (
        "Product/Doi",
        r"\b10\.\d{4,9}/[-._;()/:A-Za-z0-9]+\b",
    ),
    (
        "Product/EanUpc",
        r"\b\d{12,13}\b",
    ),
    (
        "Product/Isbn10",
        r"\b(?:\d[- ]?){9}[\dXx]\b",
    ),
    (
        "Product/Isbn13",
        r"\b97[89][- ]?(?:\d[- ]?){9}\d\b",
    ),
    (
        "Product/Orcid",
        r"\b\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b",
    ),
    (
        "Product/PubmedId",
        r"PMID:\s?\d{1,8}",
    ),

    // ---- Secrets ----------------------------------------------------------
    (
        "Secrets/AwsAccessKeyId",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    ),
    (
        "Secrets/AwsSecretKey",
        // 40 chars base64-ish. Often paired with the access-key match.
        r"\b[A-Za-z0-9/+=]{40}\b",
    ),
    (
        "Secrets/GitHubPatClassic",
        r"\bghp_[A-Za-z0-9]{36}\b",
    ),
    (
        "Secrets/Jwt",
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    ),
    (
        "Secrets/PrivateKeyHeader",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    ),
    (
        "Secrets/SlackToken",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    ),

    // ---- Versioning -------------------------------------------------------
    (
        "Versioning/GitSha256",
        r"\b[a-f0-9]{64}\b",
    ),
    (
        "Versioning/GitShaFull",
        r"\b[a-f0-9]{40}\b",
    ),
    (
        "Versioning/GitShaShort",
        r"\b[a-f0-9]{7}\b",
    ),
    (
        "Versioning/SemVer",
        r"\bv?\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\b",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_alphabetical() {
        let names: Vec<&str> = PATTERNS.iter().map(|(n, _)| *n).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "PATTERNS must be alphabetical by name");
    }

    #[test]
    fn registry_has_no_duplicates() {
        let mut names: Vec<&str> = PATTERNS.iter().map(|(n, _)| *n).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), PATTERNS.len(), "PATTERNS contains duplicate names");
    }

    #[test]
    fn every_pattern_compiles() {
        for (name, pat) in PATTERNS {
            regex::Regex::new(pat).unwrap_or_else(|e| {
                panic!("pattern {name} failed to compile: {e}\nregex: {pat}")
            });
        }
    }

    #[test]
    fn lookup_finds_known_and_misses_unknown() {
        assert!(lookup("GovernmentId/UsSsn").is_some());
        assert!(lookup("GovernmentId/Nonexistent").is_none());
    }
}
