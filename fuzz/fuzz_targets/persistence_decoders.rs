#![no_main]

use arachne_delivery::{EpochLog, current::CurrentViewIndex};
use arachne_store::FreshnessAnchor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 512 * 1024 {
        return;
    }

    let _ = FreshnessAnchor::from_bytes(data);

    if data.len() >= 77 {
        let workspace = data[5..37].try_into().unwrap();
        let owner = data[37..69].try_into().unwrap();
        let epoch = u64::from_be_bytes(data[69..77].try_into().unwrap());
        if let Ok(log) = EpochLog::restore(workspace, owner, epoch, data) {
            assert_eq!(
                EpochLog::restore(workspace, owner, epoch, &log.snapshot())
                    .unwrap()
                    .snapshot(),
                log.snapshot()
            );
        }
        if let Ok(index) = CurrentViewIndex::restore(workspace, owner, epoch, data) {
            let encoded = index.snapshot().unwrap();
            assert_eq!(
                CurrentViewIndex::restore(workspace, owner, epoch, &encoded)
                    .unwrap()
                    .snapshot()
                    .unwrap(),
                encoded
            );
        }
    }
});
