//! Generate the CustomResourceDefinition YAML for pgroles CRDs.
//!
//! Usage: `cargo run --bin crdgen > /tmp/crds.yaml`

use kube::CustomResourceExt;
use pgroles_operator::crd::{PostgresPolicy, PostgresPolicyPlan};

fn main() {
    let policy_crd = PostgresPolicy::crd();
    let policy_json =
        serde_json::to_string_pretty(&policy_crd).expect("PostgresPolicy CRD should serialize");

    let plan_crd = PostgresPolicyPlan::crd();
    let plan_json =
        serde_json::to_string_pretty(&plan_crd).expect("PostgresPolicyPlan CRD should serialize");

    println!("{policy_json}");
    println!("---");
    println!("{plan_json}");
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
