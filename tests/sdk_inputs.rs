// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

#[path = "../src/entropy.rs"]
mod entropy;
#[path = "../src/seed_input.rs"]
mod seed_input;

use bip39::Mnemonic;

#[test]
fn rejects_unsupported_raw_and_text_scans_before_sdk_conversion() {
    for len in [20, 24, 28] {
        let raw = vec![0x42; len];
        let mnemonic = Mnemonic::from_entropy(&raw).unwrap();
        for payload in [raw, mnemonic.to_string().into_bytes()] {
            assert!(security::parse_seedqr(&payload).is_ok());
            let error = seed_input::parse_seedqr(&payload).unwrap_err();
            assert!(error.contains(&format!("{} word seed", mnemonic.word_count())));
        }
        assert!(seed_input::to_sdk_seed(&mnemonic).is_err());
    }
}

#[test]
fn supported_standard_compact_and_text_scans_round_trip() {
    for len in [16, 32] {
        let raw = vec![0x42; len];
        let mnemonic = Mnemonic::from_entropy(&raw).unwrap();
        let seed = seed_input::to_sdk_seed(&mnemonic).unwrap();
        assert_eq!(seed.bytes(), raw);
        for payload in [
            seed.to_standard_seed_qr_data().unwrap(),
            seed.to_compact_seed_qr_data().unwrap(),
            mnemonic.to_string().into_bytes(),
        ] {
            let scanned = seed_input::parse_seedqr(&payload).unwrap();
            let copy = seed_input::to_sdk_seed(&scanned).unwrap();
            assert_eq!(copy.bytes(), seed.bytes());
        }
    }
}

#[test]
fn malformed_scans_are_errors() {
    for payload in [b"".as_slice(), b"not a seed", &[0xff; 17], &[0xff; 33]] {
        assert!(seed_input::parse_seedqr(payload).is_err());
    }
}

#[test]
fn a_different_supported_seed_does_not_verify() {
    let original = seed_input::to_sdk_seed(&Mnemonic::from_entropy(&[0x42; 16]).unwrap()).unwrap();
    for raw in [vec![0x43; 16], vec![0x42; 32]] {
        let scanned = seed_input::parse_seedqr(&raw).unwrap();
        assert_ne!(
            seed_input::to_sdk_seed(&scanned).unwrap().bytes(),
            original.bytes()
        );
    }
}
