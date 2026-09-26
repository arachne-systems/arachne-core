use arachne_api::{ApiError, ErrorCode, Limits, Network};
use arachne_runtime::{Client, ClientConfig, Context, ContextConfig};
use std::sync::{Arc, Barrier};

fn config() -> ClientConfig {
    ClientConfig {
        network: Network::Direct,
        secret: None,
        transport: Default::default(),
        storage: None,
    }
}

#[test]
fn client_uses_api_errors_and_its_context_limits() {
    let limits = Limits::default()
        .with_max_sessions(2)
        .with_max_overlay_paths(7);
    let context = Context::new(ContextConfig::default().with_limits(limits)).unwrap();
    let opened: Result<Arc<Client>, ApiError> = context.open(config());
    let client = opened.unwrap();
    assert_eq!(client.capabilities().unwrap().limits, limits);
    client.close().unwrap();
    assert_eq!(client.endpoint().unwrap_err().code(), ErrorCode::Closed);
}

#[cfg(not(feature = "tor"))]
#[test]
fn tor_is_a_stable_type_and_reports_unsupported_without_its_feature() {
    let mut config = config();
    config.network = Network::Tor;
    config.secret = Some([61; 32].into());
    let error: ApiError = Client::open(config).err().unwrap();
    assert_eq!(error.code(), ErrorCode::Unsupported);
}

#[test]
fn operations_racing_close_return_closed() {
    for _ in 0..32 {
        let client = Arc::new(Client::open(config()).unwrap());
        let start = Arc::new(Barrier::new(2));
        let reader = Arc::clone(&client);
        let ready = Arc::clone(&start);
        let worker = std::thread::spawn(move || {
            ready.wait();
            loop {
                match reader.endpoint() {
                    Ok(_) => std::thread::yield_now(),
                    Err(error) => {
                        assert_eq!(error.code(), ErrorCode::Closed);
                        break;
                    }
                }
            }
        });
        start.wait();
        client.close().unwrap();
        worker.join().unwrap();
    }
}

#[test]
fn foreign_secret_length_has_a_typed_input_error() {
    let mut config = arachne_runtime::default_client_config(Network::Direct);
    config.secret = Some(vec![7; 31]);
    assert_eq!(
        Client::open(config).err().unwrap().code(),
        ErrorCode::InvalidInput
    );
}
