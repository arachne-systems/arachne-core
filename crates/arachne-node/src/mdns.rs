//! mDNS address lookup that can stop and start (suspend/resume).
//!
//! `iroh-mdns-address-lookup` 0.5 has no pause, and iroh 1.2 can add an
//! address lookup service to an endpoint but not remove one. So the
//! endpoint holds this wrapper for its whole life, and the wrapper holds
//! the real mDNS service only while it runs. `pause` drops the service:
//! that ends its actor task and the swarm-discovery responder it owns, so
//! nothing is announced or answered. `start` builds a new service and gives
//! it the endpoint's current addresses.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use iroh::EndpointId;
use iroh::address_lookup::{AddressLookup, EndpointData, Error, Item};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use tokio::sync::Mutex;

use super::PeerId;

#[derive(Debug)]
struct State {
    service: Option<MdnsAddressLookup>,
    /// The endpoint's last published addresses, for a restart.
    last: Option<EndpointData>,
    listener: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Clone, Debug)]
pub(super) struct PausableMdns {
    state: Arc<StdMutex<State>>,
    /// Address sets handed to a running mDNS service to announce.
    announced: Arc<AtomicU64>,
    service_name: String,
    own: EndpointId,
    /// Endpoints seen on the local network (route hints only).
    nearby: Arc<Mutex<BTreeSet<PeerId>>>,
}

impl PausableMdns {
    /// Build and start the service. Needs a Tokio runtime context.
    pub(super) fn start_new(
        service_name: String,
        own: EndpointId,
        nearby: Arc<Mutex<BTreeSet<PeerId>>>,
    ) -> Result<Self, iroh::address_lookup::AddressLookupBuilderError> {
        let mdns = Self {
            state: Arc::new(StdMutex::new(State {
                service: None,
                last: None,
                listener: None,
            })),
            announced: Arc::default(),
            service_name,
            own,
            nearby,
        };
        mdns.start()?;
        Ok(mdns)
    }

    /// Start the service if it is stopped, and announce the last addresses.
    pub(super) fn start(&self) -> Result<(), iroh::address_lookup::AddressLookupBuilderError> {
        let mut state = self.state.lock().unwrap();
        if state.service.is_some() {
            return Ok(());
        }
        let service = MdnsAddressLookup::builder()
            .service_name(self.service_name.clone())
            .build(self.own)?;
        if let Some(last) = &state.last {
            service.publish(last);
            self.announced.fetch_add(1, Ordering::Relaxed);
        }
        state.listener = Some(self.spawn_listener(service.clone()));
        state.service = Some(service);
        Ok(())
    }

    /// Stop the service: no announcements and no answers until `start`.
    pub(super) async fn pause(&self) {
        let (service, listener) = {
            let mut state = self.state.lock().unwrap();
            (state.service.take(), state.listener.take())
        };
        if let Some(listener) = listener {
            listener.abort();
            let _ = listener.await;
        }
        // The last clone: its actor and responder end here.
        drop(service);
    }

    /// (running services, address sets announced so far): a test hook.
    pub(super) fn state(&self) -> (usize, u64) {
        let running = usize::from(self.state.lock().unwrap().service.is_some());
        (running, self.announced.load(Ordering::Relaxed))
    }

    fn spawn_listener(&self, service: MdnsAddressLookup) -> tokio::task::JoinHandle<()> {
        let nearby = self.nearby.clone();
        let own = self.own;
        tokio::spawn(async move {
            let mut events = service.subscribe().await;
            // Holds a clone until aborted; `pause` aborts it first.
            while let Some(event) = events.next().await {
                match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        let endpoint = endpoint_info.endpoint_id;
                        if endpoint != own {
                            let mut discovered = nearby.lock().await;
                            if discovered.len() < 16 {
                                discovered.insert(*endpoint.as_bytes());
                            }
                        }
                    }
                    DiscoveryEvent::Expired { endpoint_id } => {
                        nearby.lock().await.remove(endpoint_id.as_bytes());
                    }
                    _ => {}
                }
            }
        })
    }
}

impl AddressLookup for PausableMdns {
    fn publish(&self, data: &EndpointData) {
        let mut state = self.state.lock().unwrap();
        state.last = Some(data.clone());
        if let Some(service) = &state.service {
            service.publish(data);
            self.announced.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<'static, Result<Item, Error>>> {
        let state = self.state.lock().unwrap();
        state.service.as_ref()?.resolve(endpoint_id)
    }
}
