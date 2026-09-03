// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use seed_core::xor;
use zeroize::Zeroizing;

/// Draw and condition entropy for one part using Seed XOR's random mode.
pub fn draw_entropy(len: usize) -> Result<Vec<u8>, String> {
    draw_with(len, getrandom::getrandom)
}

fn draw_with(
    len: usize,
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<Vec<u8>, String> {
    let mut raw = Zeroizing::new([0u8; 32]);
    fill(&mut raw[..])
        // TODO: localize
        .map_err(|_| "Random bytes are unavailable, so no part can be generated.".to_string())?;
    Ok(xor::condition_random(&raw[..], len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_all_32_random_bytes_before_truncating() {
        for len in [16, 24, 32] {
            let result = draw_with(len, |raw| {
                assert_eq!(raw.len(), 32);
                raw.fill(0x42);
                Ok(())
            })
            .unwrap();
            assert_eq!(result, xor::condition_random(&[0x42; 32], len));
        }
    }

    #[test]
    fn random_failure_does_not_produce_a_part() {
        let result = draw_with(16, |raw| {
            raw[..4].fill(0x42);
            Err(getrandom::Error::UNSUPPORTED)
        });
        assert!(result.is_err());
    }

    #[test]
    fn hosted_random_source_can_fill_a_part() {
        assert_eq!(draw_entropy(16).unwrap().len(), 16);
        assert_eq!(draw_entropy(32).unwrap().len(), 32);
    }
}
