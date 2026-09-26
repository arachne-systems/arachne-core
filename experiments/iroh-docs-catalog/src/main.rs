//! Standalone protocol qualification. This does not grant Core workspace access.
use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use iroh::{Endpoint, EndpointAddr, SecretKey, endpoint::presets, protocol::Router};
use iroh_blobs::{BlobsProtocol, Hash, store::fs::FsStore};
use iroh_docs::{
    AuthorId, Capability, Entry, api::Doc, api::protocol::ShareMode, protocol::Docs,
    store::DownloadPolicy,
};
use iroh_gossip::net::Gossip;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, timeout};

const MANIFEST_KEY: &[u8] = b"manifest/item-1";
const CONTENT_KEY: &[u8] = b"content/item-1";

struct Peer {
    endpoint: Endpoint,
    router: Router,
    docs: Docs,
    blobs: FsStore,
}

impl Peer {
    async fn open(path: &Path, seed: u8) -> Result<Self> {
        std::fs::create_dir_all(path.join("docs"))?;
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")?
            .bind()
            .await?;
        let blobs = FsStore::load(path.join("blobs")).await?;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(path.join("docs"))
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await?;
        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs, None))
            .accept(iroh_gossip::ALPN, gossip)
            .accept(iroh_docs::ALPN, docs.clone())
            .spawn();
        Ok(Self {
            endpoint,
            router,
            docs,
            blobs,
        })
    }

    fn address(&self) -> EndpointAddr {
        EndpointAddr::new(self.endpoint.id()).with_ip_addr(self.endpoint.bound_sockets()[0])
    }

    async fn close(self) -> Result<()> {
        // Router shutdown also shuts down the Blobs and Docs stores.
        self.router.shutdown().await?;
        self.endpoint.close().await;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Manifest {
    content_hash: Hash,
    size: u64,
    complete: bool,
}

async fn entry(doc: &Doc, author: AuthorId, key: &[u8]) -> Result<Entry> {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(entry) = doc.get_exact(author, key, false).await? {
                return Ok(entry);
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("metadata sync deadline")?
}

async fn content(peer: &Peer, hash: Hash) -> Result<Bytes> {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(bytes) = peer.blobs.get_bytes(hash).await {
                return Ok(bytes);
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("content sync deadline")?
}

async fn qualify() -> Result<()> {
    let root = tempfile::tempdir()?;
    let started = std::time::Instant::now();
    let a = Peer::open(&root.path().join("a"), 1).await?;
    let b = Peer::open(&root.path().join("b"), 2).await?;
    let a_doc = a.docs.create().await?;
    let namespace = a_doc.id();
    let author = a.docs.author_create().await?;
    let payload: Vec<u8> = (0..256 * 1024).map(|index| (index % 251) as u8).collect();
    let content_hash = a_doc
        .set_bytes(author, CONTENT_KEY, payload.clone())
        .await?;
    let manifest = Manifest {
        content_hash,
        size: payload.len() as u64,
        complete: true,
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_hash = a_doc
        .set_bytes(author, MANIFEST_KEY, manifest_bytes.clone())
        .await?;
    let mut ticket = a_doc.share(ShareMode::Read, Default::default()).await?;
    ticket.nodes = vec![a.address()];
    let b_doc = b.docs.import(ticket).await?;
    ensure!(entry(&b_doc, author, MANIFEST_KEY).await?.content_hash() == manifest_hash);
    ensure!(content(&b, manifest_hash).await?.as_ref() == manifest_bytes);
    ensure!(content(&b, content_hash).await?.as_ref() == payload);
    println!("A published; B retained the original author's manifest and 262144 verified bytes");

    drop(a_doc);
    drop(b_doc);
    a.close().await?;
    b.close().await?;
    let b = Peer::open(&root.path().join("b"), 2).await?;
    let b_doc = b
        .docs
        .open(namespace)
        .await?
        .context("B lost its document after restart")?;
    ensure!(entry(&b_doc, author, MANIFEST_KEY).await?.content_hash() == manifest_hash);
    ensure!(content(&b, content_hash).await?.as_ref() == payload);
    b_doc.start_sync(vec![]).await?;
    println!("A stopped; B restarted with the retained metadata and content");

    let c = Peer::open(&root.path().join("c"), 3).await?;
    let c_doc = c.docs.import_namespace(Capability::Read(namespace)).await?;
    c_doc
        .set_download_policy(DownloadPolicy::NothingExcept(vec![]))
        .await?;
    c_doc.start_sync(vec![b.address()]).await?;
    let c_manifest = entry(&c_doc, author, MANIFEST_KEY).await?;
    let c_content = entry(&c_doc, author, CONTENT_KEY).await?;
    ensure!(c_manifest.content_hash() == manifest_hash);
    ensure!(c_content.content_hash() == content_hash);
    ensure!(c.blobs.get_bytes(manifest_hash).await.is_err());
    ensure!(c.blobs.get_bytes(content_hash).await.is_err());
    println!("C received metadata from B; neither content blob was present yet");

    // This is the standard unauthenticated-by-workspace Blobs handler. Core
    // must use its existing member/recipient grants in a production adapter.
    let connection = c.endpoint.connect(b.address(), iroh_blobs::ALPN).await?;
    for hash in [manifest_hash, content_hash] {
        c.blobs
            .remote()
            .fetch(connection.clone(), hash)
            .complete()
            .await?;
    }
    let received_manifest: Manifest = serde_json::from_slice(&content(&c, manifest_hash).await?)?;
    ensure!(received_manifest == manifest);
    ensure!(content(&c, content_hash).await?.as_ref() == payload);
    ensure!(
        c_content.author() == author,
        "holder changed the original author"
    );
    let c_author = c.docs.author_create().await?;
    ensure!(
        c_doc
            .set_bytes(c_author, b"unauthorized-write".as_slice(), b"x".as_slice())
            .await
            .is_err()
    );
    println!("C fetched and verified both blobs from B; the read capability refused a write");

    drop(c_doc);
    drop(b_doc);
    b.close().await?;
    c.close().await?;
    let c = Peer::open(&root.path().join("c"), 3).await?;
    let c_doc = c
        .docs
        .open(namespace)
        .await?
        .context("C lost its document after restart")?;
    ensure!(entry(&c_doc, author, MANIFEST_KEY).await?.content_hash() == manifest_hash);
    ensure!(content(&c, manifest_hash).await?.as_ref() == manifest_bytes);
    ensure!(content(&c, content_hash).await?.as_ref() == payload);
    drop(c_doc);
    c.close().await?;
    println!(
        "{}",
        serde_json::json!({
            "result": "pass", "payload_bytes": payload.len(), "metadata_entries": 2,
            "holder_restart": true, "receiver_restart": true, "author_offline": true,
            "metadata_does_not_imply_bytes": true, "read_only_write_rejected": true,
            "core_authorization_tested": false, "milliseconds": started.elapsed().as_millis(),
        })
    );
    Ok(())
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    timeout(Duration::from_secs(45), qualify())
        .await
        .context("qualification deadline")?
}
