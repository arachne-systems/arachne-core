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
