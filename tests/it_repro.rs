use std::cell::RefCell;
use std::rc::Rc;
use pii_tokenization_policy::*;
use pdk_unit::{Backend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};

struct EchoBackend(Rc<RefCell<Option<Vec<u8>>>>);
impl Backend for EchoBackend {
    fn call(&self, req: pdk_unit::UnitHttpRequest) -> UnitHttpResponse {
        let body = req.body().to_vec();
        *self.0.borrow_mut() = Some(body.clone());
        UnitHttpResponse::new(200).with_header("content-type", "application/json").with_body(body)
    }
}

#[test]
fn repro_503_payload() {
    let cfg = serde_json::json!({
        "maskRequestBody": true,
        "unmaskResponseBody": false,
        "contentTypeMode": "auto",
        "maskingRules": [
            {"name":"us-ssn-builtin","ruleType":"builtin","builtinPattern":"GovernmentId/UsSsn","dataType":"number","scope":"both"},
            {"name":"contract-numbers-customRegex","ruleType":"customRegex","customRegex":"\\bCN-\\d{4}-[A-Z]{3}\\b","dataType":"alphanumeric","scope":"both"},
            {"name":"premier-customer-names-static","ruleType":"static","dataType":"name","values":["Amir Khan","Johan Koeppel","Kevin Koeppner"],"scope":"both"}
        ]
    });
    let captured = Rc::new(RefCell::new(None));
    let backend = EchoBackend(captured.clone());
    let mut tester = UnitTestBuilder::default()
        .with_config(cfg.to_string())
        .with_backend(backend)
        .with_entrypoint(configure);

    let body = r#"{"prompt" : "Amir Khan with 123-45-6789 on CN-2024-EUR needs an update to the existing contract"}"#;
    let req = UnitHttpRequest::post()
        .with_path("/anything")
        .with_header("content-type", "application/json")
        .with_body(body.as_bytes().to_vec());
    let _resp = tester.request(req);
    let upstream = captured.borrow().clone().unwrap();
    let upstream_str = std::str::from_utf8(&upstream).unwrap();
    println!("\nUPSTREAM RECEIVED:\n{}\n", upstream_str);
    println!("HEX (first 200 bytes):\n{:02x?}\n", &upstream[..upstream.len().min(200)]);
    println!("LENGTH: {}\n", upstream.len());
}
