// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! The parts of this app that are pure maths.
//!
//! Deliberately free of KeyOS and Slint dependencies so it builds for the host
//! and can be tested with `cargo test -p seed-core`. Everything with a
//! correctness risk lives here, because this is the only code in the project
//! that a test can reach.

pub mod seedqr;
pub mod xor;
