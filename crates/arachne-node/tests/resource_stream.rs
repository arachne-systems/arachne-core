use arachne_node::{Node, Permissions, Topic};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};
use tokio::sync::watch;

fn digest(path: &Path) -> [u8; 32] {
    let mut file = std::fs::File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            return hash.finalize().into();
        }
        hash.update(&buffer[..n]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_resource_resumes_verified_ranges_and_enforces_grants() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let mut file = std::fs::File::create(&source).unwrap();
        let mut buffer = vec![0; 1024 * 1024];
        getrandom::fill(&mut buffer).unwrap();
        for _ in 0..101 { file.write_all(&buffer).unwrap(); }
        file.sync_all().unwrap(); drop(file); drop(buffer);
        let expected = digest(&source);
        let (holder, mut messages) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (receiver, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (other, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let workspace = [19; 32];
        let policy = BTreeMap::from([holder.id(), receiver.id(), other.id()].map(|id| (id, Permissions::AllTopics)));
        for node in [&holder, &receiver, &other] {
            node.install_verified_policy(workspace, 1, policy.clone()).await.unwrap();
            for peer in [&holder, &receiver, &other] {
                if node.id() != peer.id() { node.add_address_hint(peer.id(), peer.address()).await.unwrap(); }
            }
        }
        let from = holder.resources();
        let to = receiver.resources();
        let sender_root = directory.path().join("sender");
        let receiver_root = directory.path().join("receiver");
        let output = directory.path().join("received.bin");
        let ticket = from.prepare(&sender_root, &source, workspace, 1, receiver.id()).await.unwrap();
        assert_eq!(ticket.size, 101 * 1024 * 1024);
        // Even another legitimate member cannot use a recipient's capability.
        assert!(other.resources().fetch(&directory.path().join("other"), &directory.path().join("denied"),
            workspace, 1, holder.id(), ticket.clone(), watch::channel(0).0).await.is_err());
        let mut wrong = ticket.clone(); wrong.hash[0] ^= 1;
        assert!(to.fetch(&receiver_root, &output, workspace, 1, holder.id(), wrong, watch::channel(0).0).await.is_err());
        let mut wrong = ticket.clone(); wrong.size += 1;
        assert!(to.fetch(&receiver_root, &output, workspace, 1, holder.id(), wrong, watch::channel(0).0).await.is_err());
        assert!(!output.exists());
        let topic = Topic::new("checks/interactive").unwrap();
        holder.subscribe(workspace, 1, topic.clone()).await.unwrap();
        let (progress, mut observed) = watch::channel(0);
        let mut transfer = Box::pin(to.fetch(&receiver_root, &output, workspace, 1, holder.id(), ticket.clone(), progress));
        loop {
            tokio::select! {
                result = &mut transfer => panic!("download finished before interruption: {result:?}"),
                _ = observed.changed() => if *observed.borrow() >= 4 * 1024 * 1024 { break; }
            }
        }
        // An ordinary protected-message transport exchange remains serviceable
        // on this data connection while the large blob is in flight.
        receiver.publish(workspace, 1, topic, b"interactive".to_vec()).await.unwrap();
        assert_eq!(messages.recv().await.unwrap().payload, b"interactive");
        let interrupted_at = *observed.borrow();
        drop(transfer);
        drop(observed);
        assert!(!output.exists());
        let before = receiver.transport_metrics().received_bytes;
        let started = Instant::now();
        to.fetch(&receiver_root, &output, workspace, 1, holder.id(), ticket.clone(), watch::channel(0).0).await.unwrap();
        let received = receiver.transport_metrics().received_bytes - before;
        assert_eq!(std::fs::metadata(&output).unwrap().len(), ticket.size);
        assert_eq!(digest(&output), expected);
        assert!(received < ticket.size, "resume retransmitted the entire resource: {received}");
        println!("101 MiB verified; interrupted at {interrupted_at}; resume received {received} wire bytes in {:?}", started.elapsed());
        from.revoke(Some(&source));
        assert!(to.fetch(&receiver_root, &directory.path().join("revoked"), workspace, 1, holder.id(), ticket.clone(), watch::channel(0).0).await.is_err());
        let ticket = from.prepare(&sender_root, &source, workspace, 1, receiver.id()).await.unwrap();
        holder.install_verified_policy(workspace, 2, BTreeMap::from([(holder.id(), Permissions::AllTopics)])).await.unwrap();
        assert!(to.fetch(&receiver_root, &directory.path().join("removed"), workspace, 1, holder.id(), ticket, watch::channel(0).0).await.is_err());
        to.clear_partial(&receiver_root).await.unwrap();
        assert_eq!(digest(&source), expected, "GC must not delete an externally owned source");
        holder.close().await; receiver.close().await; other.close().await;
    }).await.unwrap();
}
