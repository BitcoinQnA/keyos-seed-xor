// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Seed XOR: split one BIP39 seed into N seeds that XOR back to it, and combine
//! N seeds back into one.
//!
//! Coldcard's scheme, from `docs/seed-xor.md` in their firmware repo. It is an
//! open standard that invites other implementations, and the vectors in the
//! tests below are theirs.
//!
//! # The algorithm
//!
//! XOR the entropy byte arrays. That is the whole thing.
//!
//! The Coldcard document describes XOR-ing 11-bit word indices while excluding
//! the checksum bits. That is the same operation said differently.
//! [`Mnemonic::to_entropy`] returns exactly the non-checksum bits (16, 24 or 32
//! bytes for 12, 18 or 24 words), so XOR-ing those arrays and re-deriving the
//! mnemonic gives an identical answer with none of the bit shuffling.
//! [`Mnemonic::from_entropy_in`] recomputes the checksum, which is what the
//! spec asks for.
//!
//! # The rules
//!
//! - 12, 18 or 24 words. Every part matches the result and the other parts.
//! - Two, three or four parts.
//! - N of N. Every part is needed. Any subset is itself a valid, and wrong, seed.
//! - The order of the parts does not matter.
//! - Each part carries its own normal BIP39 checksum, so a mistyped part is caught.
//!
//! # 18 words
//!
//! Supported here, and tested. It is the app that cannot use it: `security::Seed`
//! in the SDK only accepts 16 or 32 byte entropy and panics on 24, so nothing
//! outside this crate should build a `Seed` from an 18 word value. See the
//! README.

use bip39::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Fewest parts a seed can be split into. One part is not a split.
pub const MIN_PARTS: usize = 2;

/// Most parts a seed can be split into. Coldcard's own limit.
pub const MAX_PARTS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XorError {
    /// The parts do not all have the same word count. XOR-ing entropy of
    /// different lengths would silently truncate, so it is refused.
    LengthMismatch,
    /// Fewer than [`MIN_PARTS`] or more than [`MAX_PARTS`].
    PartCount(usize),
    /// Not 12, 18 or 24 words.
    WordCount(usize),
    /// Two of the parts are the same seed. A value XOR-ed with itself is zero,
    /// so a duplicate silently cancels both copies out and yields a different
    /// seed with no error anywhere. With two identical parts the result is
    /// all-zero entropy, which is the well known `abandon abandon ... art`
    /// wallet: a real, long-swept address rather than a failure.
    DuplicateParts,
    /// The caller supplied the wrong number of entropy pieces, or a piece of the
    /// wrong length.
    Entropy(String),
    /// bip39 rejected the words or the entropy.
    Bip39(String),
}

impl core::fmt::Display for XorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LengthMismatch => write!(f, "every part must have the same number of words"),
            Self::PartCount(n) => {
                write!(f, "{n} parts: Seed XOR takes {MIN_PARTS} to {MAX_PARTS}")
            }
            Self::WordCount(n) => write!(f, "{n} words: Seed XOR takes 12, 18 or 24"),
            Self::DuplicateParts => write!(f, "two of the parts are the same seed"),
            Self::Entropy(why) => write!(f, "{why}"),
            Self::Bip39(why) => write!(f, "{why}"),
        }
    }
}

/// Entropy bytes behind a word count, or None if BIP39 has no such length.
pub fn entropy_len(words: usize) -> Option<usize> {
    match words {
        12 => Some(16),
        18 => Some(24),
        24 => Some(32),
        _ => None,
    }
}

/// XOR any number of mnemonics together.
///
/// Also the way to make a *new* wallet out of seeds you already hold: the code
/// path is the same, only the intent differs. None of the inputs change.
pub fn combine(parts: &[Mnemonic]) -> Result<Mnemonic, XorError> {
    if parts.len() < MIN_PARTS || parts.len() > MAX_PARTS {
        return Err(XorError::PartCount(parts.len()));
    }

    let words = parts[0].word_count();
    entropy_len(words).ok_or(XorError::WordCount(words))?;
    if parts.iter().any(|p| p.word_count() != words) {
        return Err(XorError::LengthMismatch);
    }

    let entropies = Zeroizing::new(parts.iter().map(|p| p.to_entropy()).collect::<Vec<_>>());
    fold(&entropies)
}

/// Split `seed` into `count` parts, using caller-supplied entropy for the first
/// `count - 1` of them. The last part is whatever makes the set XOR back to the
/// seed.
///
/// Randomness stays out on purpose: the app passes bytes drawn from the TRNG,
/// and the tests pass fixed bytes, so the same code is exercised both times.
/// Use [`condition_random`] on raw TRNG bytes before passing them in.
pub fn split(seed: &Mnemonic, count: usize, entropy: &[Vec<u8>]) -> Result<Vec<Mnemonic>, XorError> {
    if !(MIN_PARTS..=MAX_PARTS).contains(&count) {
        return Err(XorError::PartCount(count));
    }

    let words = seed.word_count();
    let len = entropy_len(words).ok_or(XorError::WordCount(words))?;

    if entropy.len() != count - 1 {
        return Err(XorError::Entropy(format!(
            "{} parts needs {} pieces of entropy, got {}",
            count,
            count - 1,
            entropy.len()
        )));
    }
    if let Some(bad) = entropy.iter().find(|e| e.len() != len) {
        return Err(XorError::Entropy(format!(
            "a {words} word seed needs {len} bytes per part, got {}",
            bad.len()
        )));
    }

    // The last part is the seed with every other part XOR-ed out of it, so the
    // whole set folds back to the seed.
    let mut last = Zeroizing::new(seed.to_entropy());
    for piece in entropy {
        for (acc, byte) in last.iter_mut().zip(piece) {
            *acc ^= byte;
        }
    }

    let mut parts = Vec::with_capacity(count);
    for piece in entropy.iter().chain(core::iter::once(&*last)) {
        parts.push(
            Mnemonic::from_entropy_in(Language::English, piece)
                .map_err(|e| XorError::Bip39(e.to_string()))?,
        );
    }

    // Vanishingly unlikely with real randomness, but a duplicate part would make
    // the set uncombinable, so it is caught here rather than at reassembly.
    if has_duplicate(&parts) {
        return Err(XorError::DuplicateParts);
    }

    Ok(parts)
}

/// Condition raw TRNG bytes the way the spec's random mode does: double SHA-256,
/// then take the first `len` bytes.
///
/// This is the random generation mode. The deterministic mode, which hashes a
/// fixed string with the master secret and the part index, is not implemented:
/// its exact byte serialisation is not pinned down by the Coldcard document, and
/// guessing it produces parts a real Coldcard will not reproduce.
pub fn condition_random(raw: &[u8], len: usize) -> Vec<u8> {
    let mut once = Sha256::digest(raw);
    let mut twice = Sha256::digest(&once);
    once.as_mut_slice().zeroize();
    let conditioned = twice[..len.min(twice.len())].to_vec();
    twice.as_mut_slice().zeroize();
    conditioned
}

/// The last word of a mnemonic.
///
/// The spec suggests recording the original's checksum word alongside the parts,
/// so you can tell you have reassembled the right set. It gives away three bits
/// of the real seed, and it tells a holder of a correct subset that they have
/// one, so it is offered rather than done silently.
pub fn checksum_word(seed: &Mnemonic) -> String {
    seed.words().last().unwrap_or_default().to_string()
}

fn fold(entropies: &[Vec<u8>]) -> Result<Mnemonic, XorError> {
    if has_duplicate(entropies) {
        return Err(XorError::DuplicateParts);
    }

    let mut acc = Zeroizing::new(vec![0u8; entropies[0].len()]);
    for piece in entropies {
        for (out, byte) in acc.iter_mut().zip(piece) {
            *out ^= byte;
        }
    }

    Mnemonic::from_entropy_in(Language::English, &acc)
        .map_err(|e| XorError::Bip39(e.to_string()))
}

fn has_duplicate<T: PartialEq>(parts: &[T]) -> bool {
    parts.iter().enumerate().any(|(i, a)| parts[i + 1..].iter().any(|b| a == b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Coldcard's own vectors, from docs/seed-xor.md.
    const V24_A: &str = "romance wink lottery autumn shop bring dawn tongue range crater truth ability \
                         miss spice fitness easy legal release recall obey exchange recycle dragon room";
    const V24_B: &str = "lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware \
                         eager fringe sick camera series noodle toy crowd jeans select depth lounge";
    const V24_C: &str = "vault nominee cradle silk own frown throw leg cactus recall talent worry \
                         gadget surface shy planet purpose coffee drip few seven term squeeze educate";
    const V24_RESULT: &str = "silent toe meat possible chair blossom wait occur this worth option bag \
                              nurse find fish scene bench asthma bike wage world quit primary indoor";

    const V12_A: &str = "romance wink lottery autumn shop bring dawn tongue range crater truth ability";
    const V12_B: &str = "boat unfair shell violin tree robust open ride visual forest vintage approve";
    const V12_C: &str = "lion misery divide hurry latin fluid camp advance illegal lab pyramid unhappy";
    const V12_RESULT: &str = "cannon opinion leader nephew found yard metal galaxy crouch between real trade";

    fn m(phrase: &str) -> Mnemonic {
        // The vectors above are line-wrapped, so collapse the runs of spaces.
        let phrase = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
        Mnemonic::parse_in_normalized(Language::English, &phrase).expect("valid test vector")
    }

    fn phrase(seed: &Mnemonic) -> String {
        seed.words().collect::<Vec<_>>().join(" ")
    }

    /// Fixed but varied entropy, so round-trip tests are reproducible without
    /// hand-writing byte arrays for every case.
    fn fixture(tag: &str, len: usize) -> Vec<u8> {
        condition_random(tag.as_bytes(), len)
    }

    // ---- The acceptance vectors. If these fail, nothing else matters. ----

    #[test]
    fn coldcard_24_word_vector() {
        let out = combine(&[m(V24_A), m(V24_B), m(V24_C)]).expect("combines");
        assert_eq!(phrase(&out), phrase(&m(V24_RESULT)));
    }

    #[test]
    fn coldcard_12_word_vector() {
        let out = combine(&[m(V12_A), m(V12_B), m(V12_C)]).expect("combines");
        assert_eq!(phrase(&out), phrase(&m(V12_RESULT)));
    }

    // ---- Properties ----

    /// XOR is commutative, so the order the parts are entered in cannot matter.
    #[test]
    fn order_of_parts_does_not_matter() {
        let (a, b, c) = (m(V24_A), m(V24_B), m(V24_C));
        let expected = phrase(&m(V24_RESULT));

        for order in [
            [&a, &b, &c],
            [&a, &c, &b],
            [&b, &a, &c],
            [&b, &c, &a],
            [&c, &a, &b],
            [&c, &b, &a],
        ] {
            let parts: Vec<Mnemonic> = order.iter().map(|p| (*p).clone()).collect();
            assert_eq!(phrase(&combine(&parts).expect("combines")), expected);
        }
    }

    /// Split is only correct if combine inverts it, for every shape.
    #[test]
    fn split_then_combine_round_trips() {
        for words in [12usize, 18, 24] {
            let len = entropy_len(words).unwrap();
            let seed = Mnemonic::from_entropy_in(
                Language::English,
                &fixture(&format!("seed-{words}"), len),
            )
            .unwrap();

            for count in MIN_PARTS..=MAX_PARTS {
                let entropy: Vec<Vec<u8>> = (0..count - 1)
                    .map(|i| fixture(&format!("part-{words}-{count}-{i}"), len))
                    .collect();

                let parts = split(&seed, count, &entropy).expect("splits");
                assert_eq!(parts.len(), count, "{words} words into {count} parts");
                assert_eq!(
                    phrase(&combine(&parts).expect("combines")),
                    phrase(&seed),
                    "{words} words into {count} parts should round-trip"
                );
            }
        }
    }

    /// Every part has to be a seed in its own right, or it cannot be written
    /// down as words, transcribed, or typed back in.
    #[test]
    fn every_part_is_a_valid_mnemonic_of_the_same_length() {
        for words in [12usize, 18, 24] {
            let len = entropy_len(words).unwrap();
            let seed =
                Mnemonic::from_entropy_in(Language::English, &fixture(&format!("s{words}"), len))
                    .unwrap();

            for count in MIN_PARTS..=MAX_PARTS {
                let entropy: Vec<Vec<u8>> = (0..count - 1)
                    .map(|i| fixture(&format!("p{words}{count}{i}"), len))
                    .collect();

                for part in split(&seed, count, &entropy).expect("splits") {
                    assert_eq!(part.word_count(), words);
                    // Re-parsing proves the checksum is right, not just the length.
                    let reparsed = Mnemonic::parse_in_normalized(Language::English, &phrase(&part));
                    assert!(reparsed.is_ok(), "{words}/{count}: part should re-parse");
                }
            }
        }
    }

    /// The footgun the UI has to keep saying out loud: losing a part does not
    /// produce an error, it produces a different wallet. This also catches an
    /// off-by-one that silently drops a part.
    #[test]
    fn any_proper_subset_gives_a_different_seed() {
        let seed =
            Mnemonic::from_entropy_in(Language::English, &fixture("subset-seed", 32)).unwrap();
        let entropy: Vec<Vec<u8>> =
            (0..3).map(|i| fixture(&format!("subset-{i}"), 32)).collect();
        let parts = split(&seed, 4, &entropy).expect("splits");

        // Every 2 and 3 part subset of the 4.
        for skip in 0..4 {
            let three: Vec<Mnemonic> =
                parts.iter().enumerate().filter(|(i, _)| *i != skip).map(|(_, p)| p.clone()).collect();
            let out = combine(&three).expect("still a valid seed, just the wrong one");
            assert_ne!(phrase(&out), phrase(&seed), "3 of 4 (missing {skip}) must not be the seed");

            let two: Vec<Mnemonic> = three[..2].to_vec();
            let out = combine(&two).expect("still a valid seed, just the wrong one");
            assert_ne!(phrase(&out), phrase(&seed), "2 of 4 must not be the seed");
        }
    }

    #[test]
    fn mixed_word_counts_are_rejected() {
        let err = combine(&[m(V24_A), m(V12_A)]).unwrap_err();
        assert_eq!(err, XorError::LengthMismatch);
    }

    /// A part XOR-ed with itself is all-zero entropy, which is the well known
    /// `abandon abandon ... art` seed: a real wallet, swept many times over. So
    /// a user who enters the same part twice would get no error and a live
    /// address. Refuse instead.
    #[test]
    fn duplicate_parts_are_refused_rather_than_yielding_the_zero_seed() {
        let a = m(V24_A);
        assert_eq!(combine(&[a.clone(), a.clone()]).unwrap_err(), XorError::DuplicateParts);
        assert_eq!(
            combine(&[a.clone(), m(V24_B), a]).unwrap_err(),
            XorError::DuplicateParts
        );
    }

    #[test]
    fn split_rejects_duplicate_random_or_derived_parts() {
        for len in [16, 24, 32] {
            let seed = Mnemonic::from_entropy(&fixture("source", len)).unwrap();
            let part = fixture("part", len);
            assert_eq!(
                split(&seed, 3, &[part.clone(), part.clone()]).unwrap_err(),
                XorError::DuplicateParts
            );

            let zero = Mnemonic::from_entropy(&vec![0; len]).unwrap();
            assert_eq!(split(&zero, 2, &[part]).unwrap_err(), XorError::DuplicateParts);
        }
    }

    /// What that refusal is protecting against, stated as a fact rather than a
    /// claim: fold the duplicate by hand and this is what comes out.
    #[test]
    fn the_zero_seed_is_what_a_duplicate_would_have_produced() {
        let zero = Mnemonic::from_entropy_in(Language::English, &[0u8; 32]).unwrap();
        assert!(phrase(&zero).starts_with("abandon abandon abandon"));
        assert!(phrase(&zero).ends_with(" art"));
    }

    #[test]
    fn part_counts_outside_two_to_four_are_rejected() {
        let a = m(V24_A);
        assert_eq!(combine(&[a.clone()]).unwrap_err(), XorError::PartCount(1));
        assert_eq!(combine(&[]).unwrap_err(), XorError::PartCount(0));

        let five: Vec<Mnemonic> = std::iter::repeat(a.clone()).take(5).collect();
        assert_eq!(combine(&five).unwrap_err(), XorError::PartCount(5));

        let entropy = vec![fixture("x", 32)];
        assert_eq!(split(&a, 1, &entropy).unwrap_err(), XorError::PartCount(1));
        assert_eq!(split(&a, 5, &entropy).unwrap_err(), XorError::PartCount(5));
    }

    #[test]
    fn split_rejects_the_wrong_amount_of_entropy() {
        let seed = m(V24_A);
        // Three parts needs two pieces, not one.
        assert!(matches!(
            split(&seed, 3, &[fixture("a", 32)]).unwrap_err(),
            XorError::Entropy(_)
        ));
        // A 24 word seed needs 32 bytes a part, not 16.
        assert!(matches!(
            split(&seed, 2, &[fixture("a", 16)]).unwrap_err(),
            XorError::Entropy(_)
        ));
    }

    /// The recorded checksum word has to be the original's last word, not a
    /// part's.
    #[test]
    fn checksum_word_is_the_last_word_of_the_seed() {
        assert_eq!(checksum_word(&m(V24_RESULT)), "indoor");
        assert_eq!(checksum_word(&m(V12_RESULT)), "trade");
    }

    /// Random mode is double SHA-256 truncated to the entropy length, and it has
    /// to be a function of the input rather than of anything ambient.
    #[test]
    fn condition_random_is_double_sha256_truncated() {
        let raw = [0x42u8; 32];
        let expected = Sha256::digest(Sha256::digest(raw));

        for len in [16usize, 24, 32] {
            let out = condition_random(&raw, len);
            assert_eq!(out.len(), len);
            assert_eq!(out[..], expected[..len]);
        }
        assert_eq!(condition_random(&raw, 32), condition_random(&raw, 32));
        assert_ne!(condition_random(&raw, 32), condition_random(&[0x43u8; 32], 32));
    }

    /// Splitting seeds you already hold is the same operation as combining them,
    /// so the "make a new wallet from existing seeds" framing needs no new code.
    #[test]
    fn combining_existing_seeds_makes_a_new_seed_and_changes_neither_input() {
        let (a, b) = (m(V24_A), m(V24_B));
        let new = combine(&[a.clone(), b.clone()]).expect("combines");

        assert_ne!(phrase(&new), phrase(&a));
        assert_ne!(phrase(&new), phrase(&b));
        // The inputs are untouched, and the new seed splits back into them.
        assert_eq!(phrase(&combine(&[new, a.clone()]).unwrap()), phrase(&b));
        assert_eq!(phrase(&a), phrase(&m(V24_A)));
    }
}
