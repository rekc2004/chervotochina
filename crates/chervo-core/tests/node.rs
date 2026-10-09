use std::path::PathBuf;

use chervo_core::chervo_receive::ReceiveLimits;
use chervo_core::chervo_transport::NullTransport;
use chervo_core::{CoreError, Node, NodeConfig};

#[test]
fn node_start_not_implemented() {
    let cfg = NodeConfig {
        data_dir: PathBuf::from("data"),
        receive_limits: ReceiveLimits::default(),
    };
    let node = Node::new(NullTransport, cfg);
    assert!(matches!(node.start(), Err(CoreError::NotImplemented)));
    assert_eq!(node.config().data_dir, PathBuf::from("data"));
}
