use super::*;

#[test]
fn typed_publication_modes_reach_the_native_scheduler() {
    let client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([198; 32].into()),
        transport: Default::default(),
        storage: Some(StorageConfig::memory(&crate::MemoryProvider::default()).into()),
    })
    .unwrap();
    let workspace = client.create_workspace("Scheduler", None).unwrap();
    client.install_workspace_policy(1).unwrap();
    let metadata = PublicationCurrent {
        selector: [11; 32].into(),
        replacement_key: [12; 32].into(),
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        tombstone: false,
    };
    let modes = [
        (
            PublicationMode::Critical,
            arachne_node::DeliveryClass::Critical,
        ),
        (PublicationMode::Bulk, arachne_node::DeliveryClass::Bulk),
        (
            PublicationMode::Current { metadata },
            arachne_node::DeliveryClass::Current {
                replacement_key: [12; 32],
            },
        ),
    ];
    for (index, (mode, expected)) in modes.into_iter().enumerate() {
        let candidate = client
            .stage_protected_publication_with_options(
                workspace.workspace,
                1,
                "objects/options",
                [index as u8 + 1; 16].into(),
                vec![1],
                PublicationOptions {
                    recipients: vec![],
                    mode,
                },
            )
            .unwrap();
        let class = client
            .call(Op::WorkspaceState, |session| {
                let staged = session.transition.staged.as_ref().unwrap();
                match &staged.transition {
                    crate::WorkspaceTransition::RoutedPublication(_, class, _, _, _, _) => {
                        Ok(*class)
                    }
                    _ => panic!("wrong publication transition"),
                }
            })
            .unwrap();
        assert_eq!(class, expected);
        client.adopt_protected_publication(&candidate).unwrap();
    }
    client.close().unwrap();
}
