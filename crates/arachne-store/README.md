# `arachne-store`

Provides an encrypted SQLite record store with atomic updates and an
authenticated record index. The host supplies the protected root key, scope,
directory, and any external freshness anchor needed to detect whole-database
rollback.

See the [integration guide][integration] and [security model][security]. This
crate does not manage operating-system keys or host application lifecycle.

[integration]: https://github.com/arachne-systems/arachne-core/blob/main/docs/integration.md
[security]: https://github.com/arachne-systems/arachne-core/blob/main/docs/security.md
