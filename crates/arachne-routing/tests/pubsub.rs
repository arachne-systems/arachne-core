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
    // One revision behind is in the window, but the current revocation wins.
    assert_eq!(
        table.subscribe(workspace_a, 1, user, stream.clone()),
        Err(Error::Denied)
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
    assert!(table.recipients(workspace_a, 2, feed, &stream).is_ok());
    assert_eq!(
        table.recipients(workspace_a, 1, feed, &stream),
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

/// A peer one policy revision behind keeps its data (A3), but only with the
/// permissions both revisions grant. Two revisions behind is still refused.
#[test]
fn one_behind_peer_is_accepted_without_widening_permissions() {
    let topic = Topic::new("streams/sample").unwrap();
    let other = Topic::new("streams/other").unwrap();
    let (feed, user, removed, narrowed) = ([1; 32], [2; 32], [3; 32], [4; 32]);
    let workspace = [10; 32];
    let only = |topic: &Topic| Permissions::Selected {
        publish: BTreeSet::from([topic.clone()]),
        subscribe: BTreeSet::from([topic.clone()]),
    };
    let mut table = RoutingTable::default();
    table
        .install_verified_policy(
            workspace,
            1,
            BTreeMap::from([
                (feed, Permissions::AllTopics),
                (user, Permissions::AllTopics),
                (removed, Permissions::AllTopics),
                (narrowed, Permissions::AllTopics),
            ]),
        )
        .unwrap();
    table
        .install_verified_policy(
            workspace,
            2,
            BTreeMap::from([
                (feed, Permissions::AllTopics),
                (user, Permissions::AllTopics),
                (narrowed, only(&topic)),
            ]),
        )
        .unwrap();
    // A subscriber still on revision 1 announces interest; the current
    // publisher reaches it.
    table.subscribe(workspace, 1, user, topic.clone()).unwrap();
    assert!(table.subscribed(workspace, 1, user, &topic).unwrap());
    assert_eq!(
        table.recipients(workspace, 2, feed, &topic).unwrap(),
        vec![user]
    );
    // A publisher still on revision 1 reaches the current subscriber.
    assert_eq!(
        table.recipients(workspace, 1, feed, &topic).unwrap(),
        vec![user]
    );
    assert_eq!(
        table
            .direct_recipients(workspace, 1, feed, &topic, &[user])
            .unwrap(),
        vec![user]
    );
    assert_eq!(table.authorizes_endpoint(workspace, 1, feed), Ok(()));
    // Removed in the current revision: its old revision grants nothing.
    assert_eq!(
        table.recipients(workspace, 1, removed, &topic),
        Err(Error::Denied)
    );
    assert_eq!(
        table.authorizes_endpoint(workspace, 1, removed),
        Err(Error::Denied)
    );
    assert!(
        !table
            .authorized_endpoints(workspace, 1)
            .unwrap()
            .contains(&removed)
    );
    // Narrowed in the current revision: the narrower grant applies.
    assert_eq!(
        table.recipients(workspace, 1, narrowed, &other),
        Err(Error::Denied)
    );
    assert_eq!(
        table.subscribe(workspace, 1, narrowed, other.clone()),
        Err(Error::Denied)
    );
    assert!(table.recipients(workspace, 1, narrowed, &topic).is_ok());
    assert!(
        !table
            .publishers(workspace, 1, user, &other)
            .unwrap()
            .contains(&narrowed)
    );
    // Two revisions behind is outside the window.
    table
        .install_verified_policy(
            workspace,
            3,
            BTreeMap::from([
                (feed, Permissions::AllTopics),
                (user, Permissions::AllTopics),
            ]),
        )
        .unwrap();
    assert_eq!(
        table.recipients(workspace, 1, feed, &topic),
        Err(Error::WrongPolicyRevision)
    );
    assert!(table.recipients(workspace, 2, feed, &topic).is_ok());
}
