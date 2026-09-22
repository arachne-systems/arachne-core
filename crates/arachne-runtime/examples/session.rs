//! Local JSON-lines driver for the same runtime used by JNI. For harnesses and
//! source adapters; stdin/stdout carry secrets/snapshots and must not be logged.
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

fn dispatch(handle: &mut Option<i64>, command: Value) -> Result<Value, String> {
    if command["op"] == "create_session" {
        if handle.is_some() {
            return Err("session already exists".into());
        }
        let seed: [u8; 32] = serde_json::from_value(command["secret"].clone())
            .map_err(|_| "invalid endpoint seed")?;
        let created = match command.get("network").and_then(Value::as_str) {
            None | Some("direct") => arachne_runtime::create(Some(&seed))?,
            Some("wan") => arachne_runtime::create_wan(&seed)?,
            Some(_) => return Err("invalid session network".into()),
        };
        *handle = Some(created);
        return serde_json::from_str(&arachne_runtime::describe(created)?)
            .map_err(|e| e.to_string());
    }
    let current = handle.ok_or("create session first")?;
    if command["op"] == "close_session" {
        arachne_runtime::close(current)?;
        *handle = None;
        return Ok(json!({"closed":true}));
    }
    if command["op"] == "enable_record_storage" || command["op"] == "restore_record_storage" {
        let path = std::path::Path::new(
            command["path"]
                .as_str()
                .ok_or("missing private store path")?,
        );
        let root: [u8; 32] =
            serde_json::from_value(command["root"].clone()).map_err(|_| "invalid storage root")?;
        if command["op"] == "enable_record_storage" {
            arachne_runtime::enable_record_storage(current, path, &root)?;
            return Ok(json!({"durable":true}));
        }
        let workspace = serde_json::from_value(command["workspace"].clone())
            .map_err(|_| "invalid workspace")?;
        return arachne_runtime::restore_record_storage(current, path, &root, workspace);
    }
    if command["op"] == "save_candidate" {
        let token: Vec<u8> = serde_json::from_value(command["token"].clone())
            .map_err(|_| "invalid candidate token")?;
        arachne_runtime::save_candidate(current, &token)?;
        return Ok(json!({"durable":true}));
    }
    let snapshot: Vec<u8> =
        serde_json::from_value(command.get("snapshot").cloned().unwrap_or(json!([])))
            .map_err(|_| "invalid binary snapshot")?;
    let request = serde_json::to_vec(command.get("request").ok_or("missing request")?)
        .map_err(|e| e.to_string())?;
    let [metadata, snapshot] = arachne_runtime::execute_stored(current, &request, &snapshot)?;
    Ok(
        json!({"metadata":serde_json::from_slice::<Value>(&metadata).map_err(|e|e.to_string())?,
        "snapshot":snapshot}),
    )
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut handle = None;
    let result = (|| {
        loop {
            let mut line = Vec::new();
            // Binary snapshots expanded as JSON arrays plus bounded metadata.
            use std::io::Read;
            if input
                .by_ref()
                .take(4 * 1024 * 1024 + 1)
                .read_until(b'\n', &mut line)?
                == 0
            {
                break;
            }
            if line.len() > 4 * 1024 * 1024 {
                return Err(io::Error::other("local command exceeds bound"));
            }
            let reply = serde_json::from_slice(&line)
                .map_err(|e| e.to_string())
                .and_then(|command| dispatch(&mut handle, command));
            let reply = match reply {
                Ok(value) => json!({"ok":value}),
                Err(error) => json!({"error":error}),
            };
            serde_json::to_writer(&mut output, &reply)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
        Ok(())
    })();
    if let Some(handle) = handle {
        let _ = arachne_runtime::close(handle);
    }
    result
}
