// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use bip39::Mnemonic;
use zeroize::Zeroizing;

pub fn ensure_supported(mnemonic: &Mnemonic) -> Result<(), String> {
    match mnemonic.word_count() {
        12 | 24 => Ok(()),
        other => {
            // TODO: localize
            Err(format!(
                "That is a {other} word seed. This app supports only 12 and 24 word seeds."
            ))
        }
    }
}

pub fn parse_seedqr(data: &[u8]) -> Result<Mnemonic, String> {
    let mnemonic = security::parse_seedqr(data)
        // TODO: localize
        .map_err(|_| "That is not a SeedQR. Scan a Standard or Compact SeedQR.".to_string())?;
    ensure_supported(&mnemonic)?;
    Ok(mnemonic)
}

pub fn to_sdk_seed(mnemonic: &Mnemonic) -> Result<security::Seed, String> {
    // The SDK constructor aborts on lengths other than 16 or 32 bytes.
    ensure_supported(mnemonic)?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    Ok(security::Seed::from_bytes(&entropy))
}
