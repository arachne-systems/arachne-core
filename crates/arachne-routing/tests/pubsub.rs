use arachne_routing::{Error, Permissions, RoutingTable, Topic};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn scoped_feed_delivery_revocation_and_stale_policy() {
    let stream = Topic::new("streams/sample").unwrap();
    let cot = Topic::new("atak/cot").unwrap();
    let feed = [1; 32];
    let user = [2; 32];
    let outsider = [3; 32];
    let workspace_a = [10; 32];
    let workspace_b = [20; 32];
    let policy = BTreeMap::from([
        (
            feed,
            Permissions::Selected {
                publish: BTreeSet::from([stream.clone()]),
                subscribe: BTreeSet::new(),
            },
        ),
        (
            user,
            Permissions::Selected {
                publish: BTreeSet::new(),
                subscribe: BTreeSet::from([stream.clone(), cot.clone()]),
            },
        ),
    ]);
    let mut table = RoutingTable::default();
    for workspace in [workspace_a, workspace_b] {
        table
            .install_verified_policy(workspace, 1, policy.clone())
            .unwrap();
    }
    // Membership alone does not subscribe. Same peer/topic in another workspace is isolated.
    table
        .subscribe(workspace_a, 1, user, stream.clone())
        .unwrap();
    assert_eq!(
        table.recipients(workspace_a, 1, feed, &stream).unwrap(),
        vec![user]
    );
    assert!(
        table
            .recipients(workspace_b, 1, feed, &stream)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        table.recipients(workspace_a, 1, feed, &cot),
        Err(Error::Denied)
    );
    assert_eq!(
        table.recipients(workspace_a, 1, outsider, &stream),
        Err(Error::Denied)
    );
    assert_eq!(
        table.subscribe(workspace_a, 1, feed, stream.clone()),
        Err(Error::Denied)
    );
    table.unsubscribe(workspace_a, 1, user, &stream).unwrap();
    assert!(
        table
            .recipients(workspace_a, 1, feed, &stream)
            .unwrap()
            .is_empty()
    );
    table
        .subscribe(workspace_a, 1, user, stream.clone())
        .unwrap();

    let mut revoked = policy.clone();
    let Permissions::Selected { subscribe, .. } = revoked.get_mut(&user).unwrap() else {
        panic!("expected selected policy")
    };
    subscribe.clear();
    table
        .install_verified_policy(workspace_a, 2, revoked)
        .unwrap();
    assert!(
        table
            .recipients(workspace_a, 2, feed, &stream)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        table.install_verified_policy(workspace_a, 1, policy.clone()),
        Err(Error::WrongPolicyRevision)
    );
    assert_eq!(
        table.subscribe(workspace_a, 1, user, stream.clone()),
        Err(Error::WrongPolicyRevision)
    );
    assert_eq!(
        table.subscribe(workspace_a, 2, user, stream.clone()),
        Err(Error::Denied)
    );
    // Regranting permission doesn't resurrect previously revoked subscriptions.
    table
        .install_verified_policy(workspace_a, 3, policy)
        .unwrap();
    assert!(
        table
            .recipients(workspace_a, 3, feed, &stream)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        table.recipients(workspace_a, 2, feed, &stream),
        Err(Error::WrongPolicyRevision)
    );
    assert_eq!(
        table.recipients([99; 32], 3, feed, &stream),
        Err(Error::UnknownWorkspace)
    );
}

#[test]
fn invalid_topics_and_policy_limits_fail_without_replacing_policy() {
    for topic in ["", "/a", "a/", "a//b", "a/#", "a/+", "a b"] {
        assert_eq!(Topic::new(topic), Err(Error::InvalidTopic));
    }
    assert_eq!(Topic::new("a".repeat(129)), Err(Error::InvalidTopic));
    let topic = Topic::new("data").unwrap();
    let peer = [1; 32];
    let mut table = RoutingTable::default();
    table
        .install_verified_policy(
            [2; 32],
            1,
            BTreeMap::from([(
                peer,
                Permissions::Selected {
                    publish: BTreeSet::from([topic.clone()]),
                    subscribe: BTreeSet::new(),
                },
            )]),
        )
        .unwrap();
    let oversized = Permissions::Selected {
        publish: (0..65)
            .map(|i| Topic::new(format!("topic/{i}")).unwrap())
            .collect(),
        subscribe: BTreeSet::new(),
    };
    assert_eq!(
        table.install_verified_policy([2; 32], 2, BTreeMap::from([(peer, oversized)])),
        Err(Error::LimitExceeded)
    );
    assert!(table.recipients([2; 32], 1, peer, &topic).is_ok());
}
