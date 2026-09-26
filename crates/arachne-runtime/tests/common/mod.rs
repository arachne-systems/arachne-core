#[allow(dead_code)]
pub fn directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    builder.prefix("arachne-runtime-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().unwrap()
}

/// A runtime session with in-memory record storage. Sessions made with the
/// same provider share stores, so a test can close and restore.
#[allow(dead_code)]
pub fn stored(secret: &[u8; 32], provider: &arachne_runtime::MemoryProvider) -> i64 {
    let handle = arachne_runtime::create(Some(secret)).unwrap();
    attach(handle, provider);
    handle
}

/// Attach in-memory record storage to a session made by another `create*`.
#[allow(dead_code)]
pub fn attach(handle: i64, provider: &arachne_runtime::MemoryProvider) {
    arachne_runtime::attach_storage(handle, arachne_runtime::StorageConfig::memory(provider))
        .unwrap();
}
