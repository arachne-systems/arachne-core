//! Peer envelopes only. Protected publication bytes and storage formats are opaque.
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, SeqAccess, Visitor},
};

use super::{Error, MAX_FRAME, MAX_PAYLOAD, MAX_RECIPIENTS, Result};

// Schema order and enum variant indices define the sole production wire format.
const VERSION: u8 = 1;

pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // Callers bound locally constructed topic, payload and audience first.
    let bytes = postcard::to_allocvec(&(VERSION, value)).map_err(|_| Error::InvalidFrame)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_FRAME {
        return Err(Error::TooLarge);
    }
    let Some((&VERSION, body)) = bytes.split_first() else {
        return Err(Error::InvalidFrame);
    };
    let (value, trailing) = postcard::take_from_bytes(body).map_err(|_| Error::InvalidFrame)?;
    if !trailing.is_empty() {
        return Err(Error::InvalidFrame);
    }
    Ok(value)
}

pub(super) fn topic<'de, D: Deserializer<'de>>(input: D) -> std::result::Result<String, D::Error> {
    // Borrow from the bounded input before making any owned allocation.
    let topic = <&str>::deserialize(input)?;
    if topic.len() > 128 {
        return Err(D::Error::custom("topic exceeds bound"));
    }
    Ok(topic.to_owned())
}

pub(super) mod payload {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        bytes: &[u8],
        output: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        output.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        input: D,
    ) -> std::result::Result<Vec<u8>, D::Error> {
        let bytes = <&[u8]>::deserialize(input)?;
        if bytes.len() > MAX_PAYLOAD {
            return Err(D::Error::custom("payload exceeds bound"));
        }
        Ok(bytes.to_vec())
    }
}

/// Overlay envelope payloads: bounded by the frame, since membership steps
/// for a batch of admissions exceed a data publication's 16 KiB. The overlay
/// holds every other topic to `MAX_PAYLOAD` after decoding.
pub(super) mod envelope_payload {
    use super::*;

    /// Room left in a frame for the envelope's own fields.
    pub const MAX: usize = MAX_FRAME - 1024;

    pub fn serialize<S: serde::Serializer>(
        bytes: &[u8],
        output: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        output.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        input: D,
    ) -> std::result::Result<Vec<u8>, D::Error> {
        let bytes = <&[u8]>::deserialize(input)?;
        if bytes.len() > MAX {
            return Err(D::Error::custom("payload exceeds bound"));
        }
        Ok(bytes.to_vec())
    }
}

pub(super) fn recipients<'de, D: Deserializer<'de>>(
    input: D,
) -> std::result::Result<Vec<[u8; 32]>, D::Error> {
    struct Recipients;
    impl<'de> Visitor<'de> for Recipients {
        type Value = Vec<[u8; 32]>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded recipient list")
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            // Postcard supplies the declared length, or None when it cannot fit
            // in the remaining input. Reject either violation before allocation.
            let count = seq
                .size_hint()
                .filter(|n| (1..=MAX_RECIPIENTS).contains(n))
                .ok_or_else(|| A::Error::custom("recipient count exceeds bound"))?;
            let mut values = Vec::with_capacity(count);
            while let Some(value) = seq.next_element()? {
                if values.len() == count {
                    return Err(A::Error::custom("recipient count mismatch"));
                }
                values.push(value);
            }
            if values.len() != count {
                return Err(A::Error::custom("truncated recipients"));
            }
            Ok(values)
        }
    }
    input.deserialize_seq(Recipients)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeliveryClass, Frame, MAX_PAYLOAD, Operation};
    use sha2::{Digest, Sha256};

    #[test]
    fn compact_frames_preserve_every_field_without_byte_array_expansion() {
        for size in [1024, MAX_PAYLOAD] {
            let payload: Vec<_> = (0_u32..)
                .flat_map(|i| Sha256::digest(i.to_be_bytes()))
                .take(size)
                .collect();
            for (delivery_tag, delivery) in [
                DeliveryClass::Critical,
                DeliveryClass::Current {
                    replacement_key: [187; 32],
                },
                DeliveryClass::Bulk,
            ]
            .into_iter()
            .enumerate()
            {
                for (operation_tag, operation) in [
                    Operation::Subscribe,
                    Operation::Unsubscribe,
                    Operation::Publish(payload.clone()),
                    Operation::DirectPublish {
                        payload: payload.clone(),
                        recipients: vec![[199; 32], [201; 32]],
                    },
                ]
                .into_iter()
                .enumerate()
                {
                    let frame = Frame {
                        workspace: [171; 32],
                        revision: u64::MAX,
                        topic: "streams/opaque".into(),
                        delivery,
                        operation,
                    };
                    let json = serde_json::to_vec(&frame).unwrap();
                    let encoded = encode(&frame).unwrap();
                    // VERSION + workspace + max-u64 varint + topic length + topic.
                    let delivery_offset = 1 + 32 + 10 + 1 + frame.topic.len();
                    assert_eq!(encoded[delivery_offset], delivery_tag as u8);
                    let operation_offset = delivery_offset
                        + 1
                        + if matches!(delivery, DeliveryClass::Current { .. }) {
                            32
                        } else {
                            0
                        };
                    assert_eq!(encoded[operation_offset], operation_tag as u8);
                    let decoded: Frame = decode(&encoded).unwrap();
                    assert_eq!(serde_json::to_vec(&decoded).unwrap(), json);
                    assert!(
                        encoded.len() * 2 < json.len(),
                        "JSON expansion remains: {} bytes",
                        encoded.len()
                    );
                    if delivery == DeliveryClass::Critical
                        && matches!(frame.operation, Operation::Publish(_))
                    {
                        println!(
                            "direct payload={size} json={} binary={}",
                            json.len(),
                            encoded.len()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn production_wire_schema_and_untrusted_input_bounds() {
        let mut frame = Frame {
            workspace: [171; 32],
            revision: 1,
            topic: "d".into(),
            delivery: DeliveryClass::Critical,
            operation: Operation::Publish(vec![0, 255]),
        };
        let bytes = encode(&frame).unwrap();
        let mut expected = vec![1];
        expected.extend_from_slice(&[171; 32]);
        expected.extend_from_slice(&[1, 1, b'd', 0, 2, 2, 0, 255]);
        assert_eq!(bytes, expected, "unexpected production wire schema");
        for end in 0..bytes.len() {
            assert!(
                decode::<Frame>(&bytes[..end]).is_err(),
                "truncated frame accepted at {end}"
            );
        }
        for (offset, value) in [(0, 0), (0, 2), (0, 255), (35, 255), (36, 255), (37, 255)] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(decode::<Frame>(&bad).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode::<Frame>(&trailing).is_err());
        assert!(decode::<Frame>(&serde_json::to_vec(&frame).unwrap()).is_err());
        let mut forged_length = bytes[..38].to_vec();
        forged_length.extend_from_slice(&[255; 10]);
        assert!(decode::<Frame>(&forged_length).is_err());
        frame.topic = "a".repeat(129);
        assert!(decode::<Frame>(&encode(&frame).unwrap()).is_err());
        frame.topic = "a".repeat(128);
        frame.operation = Operation::Publish(vec![255; MAX_PAYLOAD + 1]);
        assert!(decode::<Frame>(&encode(&frame).unwrap()).is_err());
        for count in [0, 1, MAX_RECIPIENTS, MAX_RECIPIENTS + 1] {
            frame.operation = Operation::DirectPublish {
                payload: vec![255; MAX_PAYLOAD],
                recipients: (0..count).map(|i| [i as u8; 32]).collect(),
            };
            let encoded = encode(&frame).unwrap();
            assert_eq!(
                decode::<Frame>(&encoded).is_ok(),
                (1..=MAX_RECIPIENTS).contains(&count)
            );
            if count == 1 {
                let mut bad = encoded;
                bad.truncate(bad.len() - 33);
                bad.extend_from_slice(&[255; 10]);
                assert!(decode::<Frame>(&bad).is_err());
            }
        }
        assert!(matches!(
            decode::<Frame>(&vec![1; MAX_FRAME + 1]),
            Err(Error::TooLarge)
        ));
        assert!(matches!(
            encode(&vec![2_u8; MAX_FRAME]),
            Err(Error::TooLarge)
        ));
    }

    #[test]
    #[ignore = "prints synthetic payload/ciphertext samples for offline compression measurement"]
    fn compression_samples() {
        let mut owner = arachne_security::Workspace::create([1; 32], "Wire measurement").unwrap();
        let observation = br#"{"sensor":"demo-1","observed_at":"2026-09-15T12:00:00Z","latitude":41.2,"longitude":-87.3,"altitude_m":1200,"speed_mps":85,"heading_deg":270,"status":"active"}"#.to_vec();
        let batch = serde_json::to_vec(
            &(0..32)
                .map(|i| {
                    serde_json::json!({
                        "sensor":format!("demo-{i}"), "observed_at":"2026-09-15T12:00:00Z",
                        "latitude":41.2 + f64::from(i) / 100.0, "longitude":-87.3,
                        "altitude_m":1200 + i, "speed_mps":85, "heading_deg":270, "status":"active",
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let opaque: Vec<_> = (0_u32..)
            .flat_map(|i| Sha256::digest(i.to_be_bytes()))
            .take(8192)
            .collect();
        for (name, plaintext) in [
            ("observation", observation),
            ("observation-batch", batch),
            ("opaque", opaque),
        ] {
            let ciphertext = owner
                .protect_application(b"wire-measurement", &plaintext)
                .unwrap();
            let frame = Frame {
                workspace: owner.id(),
                revision: 1,
                topic: "streams/opaque".into(),
                delivery: DeliveryClass::Critical,
                operation: Operation::Publish(ciphertext.clone()),
            };
            let binary = encode(&frame).unwrap();
            let decoded: Frame = decode(&binary).unwrap();
            let Operation::Publish(received) = decoded.operation else {
                panic!("changed operation")
            };
            assert_eq!(received, ciphertext);
            println!(
                "COMPRESSION_SAMPLE {}",
                serde_json::json!({
                    "name":name, "plaintext":plaintext, "ciphertext":ciphertext,
                    "binary":binary, "json":serde_json::to_vec(&frame).unwrap(),
                })
            );
        }
    }
}
