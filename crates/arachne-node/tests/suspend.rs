use arachne_node::Node;

fn send_future<T: Send>(future: T) -> T {
    future
}

#[tokio::test]
async fn suspend_and_resume_futures_can_move_between_workers() {
    let (node, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    send_future(node.suspend()).await;
    assert!(node.is_suspended());
    send_future(node.resume()).await;
    assert!(!node.is_suspended());
    node.close().await;
}
