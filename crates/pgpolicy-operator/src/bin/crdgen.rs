//! Generate the CustomResourceDefinition YAML for `PostgresPolicy`.
//!
//! Usage: `cargo run --bin crdgen > k8s/crd.yaml`

use kube::CustomResourceExt;
use pgpolicy_operator::crd::PostgresPolicy;

fn main() {
    let crd = PostgresPolicy::crd();
    let yaml = serde_yaml::to_string(&crd).expect("CRD should serialize to YAML");
    print!("{yaml}");
}
