use std::{collections::BTreeSet, net::SocketAddr, time::Duration};

use futures_util::StreamExt;
use iroh::address_lookup::{AddressLookup, EndpointData};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};

#[tokio::test]
async fn a_later_lookup_uses_the_peers_changed_port() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let local = iroh::SecretKey::from_bytes(&[91; 32]).public();
        let peer = iroh::SecretKey::from_bytes(&[92; 32]).public();
        let service = format!("arachne-refresh-{}", std::process::id());
        let lookup = MdnsAddressLookup::builder()
            .service_name(service.clone())
            .advertise(false)
            .build(local)
            .unwrap();
        let advertiser = MdnsAddressLookup::builder()
            .service_name(service)
            .build(peer)
            .unwrap();
        let mut events = lookup.subscribe().await;
        for port in [11111, 22222] {
            let address: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
            advertiser.publish(&EndpointData::from(BTreeSet::from([address])));
            loop {
                if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) = events.next().await
                    && endpoint_info.endpoint_id == peer
                    && endpoint_info
                        .data
                        .ip_addrs()
                        .any(|addr| addr.port() == port)
                {
                    break;
                }
            }
        }
        // The update arrived before this dial needed lookup. Its cache must
        // retain the new address, even though no resolver was waiting then.
        let item = lookup.resolve(peer).unwrap().next().await.unwrap().unwrap();
        let ports: BTreeSet<_> = item
            .endpoint_info()
            .data
            .ip_addrs()
            .map(|a| a.port())
            .collect();
        assert_eq!(
            ports,
            BTreeSet::from([22222]),
            "lookup returned the pre-restart port"
        );
    })
    .await
    .expect("mDNS did not report the address change");
}
