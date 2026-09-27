#![no_main]

use arachne_runtime::{
    MAX_REQUEST, execute_stored_with_code, execute_with_code, inspect_invitation,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_REQUEST {
        return;
    }

    let _ = execute_with_code(i64::MIN, data);
    let _ = inspect_invitation(data);

    let split = data.len() / 2;
    let _ = execute_stored_with_code(i64::MIN, &data[..split], &data[split..]);
});
