//! Application-owned DTO mapping at a Rust/Dart boundary; no FRB dependency here.
use x509_info::{parse_pem_with_names, ExtensionDetails, GeneralName, OidNames, ParseOptions};

// In a Console binding crate, expose this application type through FRB.
#[derive(Debug)]
struct CertificateView {
    subject: String,
    dns_names: Vec<String>,
    sha256: String,
}

fn certificate_view(pem: Vec<u8>) -> Result<CertificateView, x509_info::Error> {
    let names = OidNames::default();
    let info = parse_pem_with_names(&pem, ParseOptions::default(), &names)?;
    // Parsing copies data and labels; neither input nor configuration is retained.
    drop(pem);
    drop(names);
    let summary = info.summary();
    // The same summary model also serves the export_json example.
    drop(info);

    // UI policy belongs here: this view only needs DNS identities. A complete
    // inspector should also display unsupported/malformed/duplicate findings.
    let dns_names = summary
        .extensions
        .iter()
        .flat_map(|e| match &e.details {
            ExtensionDetails::SubjectAlternativeName(names) => names.as_slice(),
            _ => &[],
        })
        .filter_map(|name| match name {
            GeneralName::Dns(s) => Some(s.clone()),
            _ => None,
        })
        .collect();
    Ok(CertificateView {
        subject: summary.subject.display,
        dns_names,
        sha256: summary.sha256_fingerprint_hex,
    })
} // Input, full result and temporary summary are dropped; DTO fields remain owned.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let view = certificate_view(include_bytes!("../tests/fixtures/details.pem").to_vec())?;
    println!(
        "{}\nDNS: {:?}\nSHA-256: {}",
        view.subject, view.dns_names, view.sha256
    );
    Ok(())
}
