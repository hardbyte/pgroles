//! Generate the CustomResourceDefinition YAML for `PostgresPolicy`.
//!
//! Usage: `cargo run --bin crdgen > k8s/crd.yaml`

use kube::CustomResourceExt;
use pgpolicy_operator::crd::PostgresPolicy;

fn main() {
    let crd = PostgresPolicy::crd();
    let json = serde_json::to_string_pretty(&crd).expect("CRD should serialize to JSON");
    println!("{json}");
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt;
    use pgpolicy_operator::crd::PostgresPolicy;

    #[test]
    fn crd_serializes_to_json() {
        let crd = PostgresPolicy::crd();
        let json = serde_json::to_string_pretty(&crd).expect("CRD should serialize");
        assert!(json.contains("\"apiVersion\""));
        assert!(json.contains("\"PostgresPolicy\""));
    }
}
