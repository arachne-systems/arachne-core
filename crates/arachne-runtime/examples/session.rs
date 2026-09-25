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
    if command["op"] == "attach_storage" {
        let directory = std::path::Path::new(
            command["directory"]
                .as_str()
                .ok_or("missing private store directory")?,
        );
        let root: [u8; 32] =
            serde_json::from_value(command["root"].clone()).map_err(|_| "invalid storage root")?;
        arachne_runtime::attach_storage(
            current,
            arachne_runtime::StorageConfig::sqlite(directory, root),
        )?;
        return Ok(json!({"attached":true}));
    }
    let request = command.get("request").ok_or("missing request")?;
    // A binary Welcome (stage_join) never fits a JSON request; every other op
    // travels as plain JSON, its candidate token an ordinary field.
    if request["op"] == "stage_join" {
        let welcome: Vec<u8> =
            serde_json::from_value(request.get("welcome").cloned().unwrap_or(json!([])))
                .map_err(|_| "invalid binary welcome")?;
        let mut metadata = request.clone();
        metadata
            .as_object_mut()
            .ok_or("request must be an object")?
            .remove("welcome");
        let encoded = serde_json::to_vec(&metadata).map_err(|e| e.to_string())?;
        let response = arachne_runtime::execute_stored(current, &encoded, &welcome)?;
        return serde_json::from_slice(&response).map_err(|e| e.to_string());
    }
    let encoded = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    let response = arachne_runtime::execute(current, &encoded)?;
    serde_json::from_slice(&response).map_err(|e| e.to_string())
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
