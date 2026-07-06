#![no_main]
//! Fuzz the frame decoder — the pre-auth attack surface. `decode` and `parse_len`
//! run on attacker-controlled bytes before any authentication, so they must never
//! panic, hang, or over-allocate on arbitrary input.

use libfuzzer_sys::fuzz_target;
use quish_proto::{ChannelMessage, ChannelOpen, LEN_PREFIX, decode, parse_len};

fuzz_target!(|data: &[u8]| {
    // Bare body decode for both frame enums.
    let _ = decode::<ChannelMessage>(data);
    let _ = decode::<ChannelOpen>(data);

    // Full framed path: parse the length prefix, then decode the bounded body.
    if data.len() >= LEN_PREFIX {
        let prefix: [u8; LEN_PREFIX] = data[..LEN_PREFIX].try_into().unwrap();
        if let Ok(len) = parse_len(prefix) {
            let body = &data[LEN_PREFIX..];
            let take = len.min(body.len());
            let _ = decode::<ChannelMessage>(&body[..take]);
        }
    }
});
