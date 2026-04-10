//! Generate CustomResourceDefinition files for pgroles CRDs.
//!
//! Usage: `cargo run --bin crdgen -- --output-dir charts/pgroles-operator/crds/`
//! Without --output-dir, prints all CRDs to stdout separated by `---`.

use std::path::PathBuf;

use kube::CustomResourceExt;
use pgroles_operator::crd::{PostgresPolicy, PostgresPolicyPlan};

struct CrdOutput {
    filename: &'static str,
    json: String,
}

fn generate() -> Vec<CrdOutput> {
    vec![
        CrdOutput {
            filename: "postgrespolicies.pgroles.io.yaml",
            json: serde_json::to_string_pretty(&PostgresPolicy::crd())
                .expect("PostgresPolicy CRD should serialize"),
        },
        CrdOutput {
            filename: "postgrespolicyplans.pgroles.io.yaml",
            json: serde_json::to_string_pretty(&PostgresPolicyPlan::crd())
                .expect("PostgresPolicyPlan CRD should serialize"),
        },
    ]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if let Some(pos) = args.iter().position(|a| a == "--output-dir") {
        let dir = PathBuf::from(args.get(pos + 1).expect("--output-dir requires a path"));
        std::fs::create_dir_all(&dir).expect("failed to create output directory");
        for crd in generate() {
            let path = dir.join(crd.filename);
            std::fs::write(&path, format!("{}\n", crd.json))
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            eprintln!("wrote {}", path.display());
        }
    } else {
        let crds = generate();
        for (i, crd) in crds.iter().enumerate() {
            if i > 0 {
                println!("---");
            }
            println!("{}", crd.json);
        }
    }
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt;
    use pgroles_operator::crd::{PostgresPolicy, PostgresPolicyPlan};

    #[test]
    fn policy_crd_serializes_to_json() {
        let crd = PostgresPolicy::crd();
        let json = serde_json::to_string_pretty(&crd).expect("CRD should serialize");
        assert!(json.contains("\"apiVersion\""));
        assert!(json.contains("\"PostgresPolicy\""));
    }

    #[test]
    fn plan_crd_serializes_to_json() {
        let crd = PostgresPolicyPlan::crd();
        let json = serde_json::to_string_pretty(&crd).expect("CRD should serialize");
        assert!(json.contains("\"apiVersion\""));
        assert!(json.contains("\"PostgresPolicyPlan\""));
        assert!(json.contains("\"pgplan\""));
    }
}
