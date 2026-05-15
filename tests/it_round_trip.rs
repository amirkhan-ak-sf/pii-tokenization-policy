//! End-to-end integration tests using `pdk-unit`'s in-process Proxy-Wasm
//! stub. Wires a single mock upstream that captures the masked request
//! body and echoes a response containing those same masks; the test then
//! asserts that the policy unmasks the response correctly.

use std::cell::RefCell;
use std::rc::Rc;

use data_masking_policy::*;
use pdk_unit::{Backend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};

struct EchoBackend {
    captured: Rc<RefCell<Option<Vec<u8>>>>,
    response_body: Rc<RefCell<Option<Vec<u8>>>>,
}

impl EchoBackend {
    fn new() -> (Self, Rc<RefCell<Option<Vec<u8>>>>, Rc<RefCell<Option<Vec<u8>>>>) {
        let captured: Rc<RefCell<Option<Vec<u8>>>> = Rc::new(RefCell::new(None));
        let response_body: Rc<RefCell<Option<Vec<u8>>>> = Rc::new(RefCell::new(None));
        let me = Self {
            captured: captured.clone(),
            response_body: response_body.clone(),
        };
        (me, captured, response_body)
    }
}

impl Backend for EchoBackend {
    fn call(&self, req: UnitHttpRequest) -> UnitHttpResponse {
        // `req.body()` contains exactly the bytes the upstream would
        // see — i.e. the body after the policy has masked it.
        let body = req.body().to_vec();
        *self.captured.borrow_mut() = Some(body.clone());

        // Default echo: send the masked body straight back so the unmask
        // path has something to reverse. Tests can override the response
        // body via `response_body`.
        let resp_body = self
            .response_body
            .borrow()
            .clone()
            .unwrap_or(body);

        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_body(resp_body)
    }
}

fn ssn_re() -> regex::Regex {
    regex::Regex::new(r"\d{3}-\d{2}-\d{4}").unwrap()
}

fn build_tester(
    config_json: serde_json::Value,
) -> (
    pdk_unit::UnitTest,
    Rc<RefCell<Option<Vec<u8>>>>,
    Rc<RefCell<Option<Vec<u8>>>>,
) {
    let (backend, captured, response_body) = EchoBackend::new();
    let tester = UnitTestBuilder::default()
        .with_config(config_json.to_string())
        .with_backend(backend)
        .with_entrypoint(configure);
    (tester, captured, response_body)
}

#[test]
fn ssn_round_trip_with_json_aware() {
    let cfg = serde_json::json!({
        "maskRequestBody": true,
        "unmaskResponseBody": true,
        "contentTypeMode": "auto",
        "maskingRules": [
            {
                "name": "ssn",
                "type": "builtin",
                "builtinPattern": "GovernmentId/UsSsn",
                "dataType": "number",
                "scope": "both"
            }
        ]
    });

    let (mut tester, captured, _resp) = build_tester(cfg);

    let body = serde_json::json!({
        "customer": "Amir Khan",
        "ssn": "123-45-6789"
    })
    .to_string();

    let req = UnitHttpRequest::post()
        .with_path("/anything")
        .with_header("content-type", "application/json")
        .with_body(body.into_bytes());

    let resp = tester.request(req);
    assert_eq!(resp.status_code(), 200);

    // 1) The upstream must NOT have seen the original SSN.
    let upstream_body = captured.borrow().clone().expect("upstream captured a body");
    let upstream_text = std::str::from_utf8(&upstream_body).unwrap();
    assert!(
        !upstream_text.contains("123-45-6789"),
        "upstream still saw the original SSN: {upstream_text}"
    );
    // 2) The masked variant must still be SSN-shaped.
    assert!(
        ssn_re().is_match(upstream_text),
        "upstream body is not SSN-shaped: {upstream_text}"
    );

    // 3) The client (i.e. the response body returned from the tester)
    //    must see the original value back.
    let client_body = std::str::from_utf8(resp.body()).unwrap();
    assert!(
        client_body.contains("123-45-6789"),
        "client did not see the original SSN: {client_body}"
    );
}

#[test]
fn static_list_with_thousands_of_entries() {
    let mut names: Vec<serde_json::Value> = (0..10_000)
        .map(|i| serde_json::Value::String(format!("Customer{i:05}")))
        .collect();
    // Sprinkle 5 known names in the list at random-ish positions.
    let known = ["Amir Khan", "Johan Koeppel", "Thomas Koeppner", "Jane Doe", "John Smith"];
    for (i, n) in known.iter().enumerate() {
        names[i * 1000] = serde_json::Value::String((*n).into());
    }

    let cfg = serde_json::json!({
        "maskRequestBody": true,
        "unmaskResponseBody": true,
        "contentTypeMode": "text",
        "maskingRules": [
            {
                "name": "premier-customers",
                "type": "static",
                "dataType": "name",
                "values": names,
                "scope": "both"
            }
        ]
    });

    let (mut tester, captured, _resp) = build_tester(cfg);

    let body = "Customers Amir Khan, Johan Koeppel, Thomas Koeppner are at risk; \
                so are Jane Doe and John Smith. Customer Customer09999 is fine.";

    let req = UnitHttpRequest::post()
        .with_path("/anything")
        .with_header("content-type", "text/plain")
        .with_body(body.as_bytes().to_vec());

    let resp = tester.request(req);
    assert_eq!(resp.status_code(), 200);

    let upstream_body = captured.borrow().clone().unwrap();
    let upstream_text = std::str::from_utf8(&upstream_body).unwrap();
    for n in &known {
        assert!(
            !upstream_text.contains(n),
            "upstream still saw '{n}': {upstream_text}"
        );
    }
    // The unrelated value must NOT have been masked (unless coincidence).
    // We only know it shouldn't have been replaced into one of the
    // known-name masks; we don't enforce its survival here.

    let client_text = std::str::from_utf8(resp.body()).unwrap();
    for n in &known {
        assert!(
            client_text.contains(n),
            "client did not see '{n}' restored: {client_text}"
        );
    }
}

#[test]
fn unmask_response_body_off_means_client_sees_mask() {
    let cfg = serde_json::json!({
        "maskRequestBody": true,
        "unmaskResponseBody": false,
        "contentTypeMode": "text",
        "maskingRules": [
            {
                "name": "ssn",
                "type": "builtin",
                "builtinPattern": "GovernmentId/UsSsn",
                "dataType": "number",
                "scope": "both"
            }
        ]
    });

    let (mut tester, captured, _resp) = build_tester(cfg);

    let body = "SSN on file: 123-45-6789.";
    let req = UnitHttpRequest::post()
        .with_path("/anything")
        .with_header("content-type", "text/plain")
        .with_body(body.as_bytes().to_vec());

    let resp = tester.request(req);
    let upstream = captured.borrow().clone().unwrap();
    let upstream_text = std::str::from_utf8(&upstream).unwrap();
    assert!(!upstream_text.contains("123-45-6789"));
    let client_text = std::str::from_utf8(resp.body()).unwrap();
    assert!(
        !client_text.contains("123-45-6789"),
        "client should also see the mask (unmaskResponseBody=false), got {client_text}"
    );
}

#[test]
fn empty_rules_list_passes_through() {
    let cfg = serde_json::json!({
        "maskingRules": []
    });

    let (mut tester, captured, _resp) = build_tester(cfg);

    let body = "the original body, unchanged";
    let req = UnitHttpRequest::post()
        .with_path("/anything")
        .with_header("content-type", "text/plain")
        .with_body(body.as_bytes().to_vec());

    let _ = tester.request(req);
    let upstream = captured.borrow().clone().unwrap();
    assert_eq!(upstream, body.as_bytes());
}

#[test]
fn json_keys_are_preserved() {
    let cfg = serde_json::json!({
        "maskingRules": [
            {
                "name": "names",
                "type": "static",
                "dataType": "name",
                "values": ["name", "Amir Khan"],
                "scope": "both"
            }
        ]
    });

    let (mut tester, captured, _resp) = build_tester(cfg);

    // The literal "name" appears as both a key and as a substring of a
    // value. JSON-aware mode must mask the value but leave the key
    // untouched (otherwise the JSON becomes unparseable).
    let body = serde_json::json!({"name": "Amir Khan"}).to_string();
    let req = UnitHttpRequest::post()
        .with_path("/anything")
        .with_header("content-type", "application/json")
        .with_body(body.into_bytes());

    let _ = tester.request(req);
    let upstream = captured.borrow().clone().unwrap();
    let text = std::str::from_utf8(&upstream).unwrap();
    // The key 'name' must remain.
    assert!(text.contains("\"name\":"), "key 'name' missing: {text}");
    // The value 'Amir Khan' must be replaced.
    assert!(!text.contains("Amir Khan"), "value still present: {text}");
}
