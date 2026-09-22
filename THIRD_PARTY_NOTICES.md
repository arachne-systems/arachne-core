# Third-party notices

This index covers source checked into [`vendor/`](vendor/). Each component's
license text is retained in its directory, and any local changes are described
in its `ARACHNE-PATCH.md`. These components are not relicensed under the Core
repository's MPL-2.0 license.

| Component | Version | License | Upstream | Local record |
| --- | --- | --- | --- | --- |
| `bao-tree` | 0.16.1 | MIT OR Apache-2.0 | [n0-computer/bao-tree](https://github.com/n0-computer/bao-tree) | [licenses](vendor/bao-tree/) · [patch notes](vendor/bao-tree/ARACHNE-PATCH.md) |
| `hax-lib-macros` | 0.3.7 | Apache-2.0 | [hacspec/hax](https://github.com/hacspec/hax) | [license](vendor/hax-lib-macros/LICENSE) · [patch notes](vendor/hax-lib-macros/ARACHNE-PATCH.md) |
| `iroh-blobs` | 0.103.0 | MIT OR Apache-2.0 | [n0-computer/iroh-blobs](https://github.com/n0-computer/iroh-blobs) | [licenses](vendor/iroh-blobs/) · [patch notes](vendor/iroh-blobs/ARACHNE-PATCH.md) |
| `iroh-gossip` | 0.101.0 | MIT OR Apache-2.0 | [n0-computer/iroh-gossip](https://github.com/n0-computer/iroh-gossip) | [licenses](vendor/iroh-gossip/) · [patch notes](vendor/iroh-gossip/ARACHNE-PATCH.md) |
| `netlink-packet-core` | 0.8.2 | MIT | [rust-netlink/netlink-packet-core](https://github.com/rust-netlink/netlink-packet-core) | [license](vendor/netlink-packet-core/LICENSE-MIT) · [patch notes](vendor/netlink-packet-core/ARACHNE-PATCH.md) |

This is an inventory of in-tree vendored source, not a complete inventory of
packages fetched by Cargo. Registry dependencies retain their own terms and are
version-pinned in [`Cargo.lock`](Cargo.lock). Generate notices for the exact
platform and feature set before distributing a binary.
