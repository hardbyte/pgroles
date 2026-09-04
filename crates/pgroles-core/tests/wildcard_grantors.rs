use pgroles_core::{
    diff::{Change, diff},
    manifest::{ObjectType, Privilege},
    model::{GrantKey, GrantState, Grantee, RoleGraph},
};
use std::collections::{BTreeMap, BTreeSet};

fn key(name: &str) -> GrantKey {
    GrantKey {
        role: Grantee::Role("reader".into()),
        object_type: ObjectType::Table,
        schema: Some("app".into()),
        name: Some(name.into()),
    }
}

#[test]
fn collapsed_revokes_use_concrete_grantors_and_preserve_owned_objects() {
    let mut current = RoleGraph::default();
    current.grants.insert(
        key("*"),
        GrantState {
            privileges: BTreeSet::from([Privilege::Select]),
        },
    );
    current.inherent_grants.insert(key("owned"));
    for object in ["b", "a"] {
        current.grant_entry_grantors.insert(
            key(object),
            BTreeMap::from([
                ("delegate2".into(), BTreeSet::from([Privilege::Select])),
                ("delegate1".into(), BTreeSet::from([Privilege::Select])),
            ]),
        );
    }
    let changes = diff(&current, &RoleGraph::default());
    let expected: Vec<_> = ["a", "b"]
        .into_iter()
        .flat_map(|object| {
            ["delegate1", "delegate2"]
                .into_iter()
                .map(move |grantor| Change::Revoke {
                    role: Grantee::Role("reader".into()),
                    object_type: ObjectType::Table,
                    schema: Some("app".into()),
                    name: Some(object.into()),
                    grantor: Some(grantor.into()),
                    privileges: BTreeSet::from([Privilege::Select]),
                })
        })
        .collect();
    assert_eq!(changes, expected);
}
