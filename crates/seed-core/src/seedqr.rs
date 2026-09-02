// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! SeedQR grid geometry: turn a SeedQR payload into a module matrix, and split
//! that matrix into the blocks the transcription screen walks through.

use qrcode::{EcLevel, QrCode};

/// Modules per side of one transcription block.
pub const BLOCK: usize = 7;

/// A SeedQR is always error correction level L at the smallest version that
/// fits. Anything else changes the grid size and stops matching the spec.
const EC_LEVEL: EcLevel = EcLevel::L;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError(pub String);

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "{}", self.0) }
}

/// What to mark in one cell of a transcription block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cell {
    /// Inside the code, leave blank.
    Light = 0,
    /// Inside the code, mark it.
    Dark = 1,
    /// Past the edge of the code. Not part of the grid at all.
    Outside = 2,
}

impl Cell {
    pub fn as_i32(self) -> i32 { self as i32 }
}

pub struct Grid {
    width: usize,
    modules: Vec<bool>,
}

impl Grid {
    /// Encode a SeedQR payload. Standard payloads are ASCII digits, compact
    /// payloads are raw entropy bytes; the encoder picks numeric or byte mode.
    pub fn build(payload: &[u8]) -> Result<Self, BuildError> {
        let code = QrCode::with_error_correction_level(payload, EC_LEVEL)
            .map_err(|e| BuildError(format!("could not build the code: {e}")))?;

        let width = code.width();
        let modules = code.to_colors().into_iter().map(|c| c == qrcode::Color::Dark).collect();

        Ok(Self { width, modules })
    }

    pub fn width(&self) -> usize { self.width }

    pub fn blocks_across(&self) -> usize { self.width.div_ceil(BLOCK) }

    pub fn block_count(&self) -> usize {
        let across = self.blocks_across();
        across * across
    }

    /// True when the module at (row, col) should be marked. Out of range reads
    /// are light rather than a panic, since the last block runs past the edge.
    pub fn is_dark(&self, row: usize, col: usize) -> bool {
        row < self.width && col < self.width && self.modules[row * self.width + col]
    }

    /// Top-left module of a block, as (row, col).
    pub fn block_origin(&self, index: usize) -> (usize, usize) {
        let across = self.blocks_across();
        ((index / across) * BLOCK, (index % across) * BLOCK)
    }

    /// Inclusive 1-based extent of a block, clamped to the code: (row_from,
    /// row_to, col_from, col_to). What the transcription screen puts in its
    /// subtitle.
    pub fn block_extent(&self, index: usize) -> (usize, usize, usize, usize) {
        let (row0, col0) = self.block_origin(index);
        (row0 + 1, (row0 + BLOCK).min(self.width), col0 + 1, (col0 + BLOCK).min(self.width))
    }

    /// One entry per cell of the block, row-major.
    pub fn block_cells(&self, index: usize) -> Vec<Cell> {
        let (row0, col0) = self.block_origin(index);
        let mut cells = Vec::with_capacity(BLOCK * BLOCK);
        for row in row0..row0 + BLOCK {
            for col in col0..col0 + BLOCK {
                cells.push(if row >= self.width || col >= self.width {
                    Cell::Outside
                } else if self.is_dark(row, col) {
                    Cell::Dark
                } else {
                    Cell::Light
                });
            }
        }
        cells
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic};

    // SeedSigner's own test vectors, docs/seed_qr/README.md
    const V12: &str = "attack pizza motion avocado network gather crop fresh patrol unusual wild holiday";
    const V24: &str = "attack pizza motion avocado network gather crop fresh patrol unusual wild holiday \
                       candy pony ranch winter theme error hybrid van cereal salon goddess expire";

    fn mnemonic(phrase: &str) -> Mnemonic {
        Mnemonic::parse_in_normalized(Language::English, phrase).expect("valid test vector")
    }

    /// Mirrors security::Seed::to_standard_seed_qr_data
    fn standard(m: &Mnemonic) -> Vec<u8> {
        m.word_indices().map(|i| format!("{i:04}")).collect::<String>().into_bytes()
    }

    /// Mirrors security::Seed::to_compact_seed_qr_data
    fn compact(m: &Mnemonic) -> Vec<u8> { m.to_entropy() }

    fn cases() -> Vec<(&'static str, Vec<u8>, usize)> {
        let m12 = mnemonic(V12);
        let m24 = mnemonic(V24);
        vec![
            ("12 standard", standard(&m12), 25),
            ("12 compact", compact(&m12), 21),
            ("24 standard", standard(&m24), 29),
            ("24 compact", compact(&m24), 25),
        ]
    }

    #[test]
    fn payload_lengths_match_the_spec() {
        let m12 = mnemonic(V12);
        let m24 = mnemonic(V24);
        assert_eq!(standard(&m12).len(), 48);
        assert_eq!(compact(&m12).len(), 16);
        assert_eq!(standard(&m24).len(), 96);
        assert_eq!(compact(&m24).len(), 32);
    }

    #[test]
    fn grid_sizes_match_the_spec() {
        for (label, payload, expected) in cases() {
            let grid = Grid::build(&payload).expect("builds");
            assert_eq!(grid.width(), expected, "{label} should be {expected}x{expected}");
        }
    }

    /// The error correction level is load bearing, but only for the compact
    /// format. A 16 byte payload fits a 21x21 at level L and not at level M, and
    /// a 32 byte payload fits a 25x25 at level L and not at level M, so building
    /// with the wrong level silently produces a larger grid than the spec.
    /// Standard payloads happen to fit either way at these sizes.
    #[test]
    fn error_correction_level_is_load_bearing_for_compact() {
        let level_m = |payload: &[u8]| {
            QrCode::with_error_correction_level(payload, EcLevel::M).unwrap().width()
        };

        for (label, payload, expected) in cases() {
            let ours = Grid::build(&payload).unwrap().width();
            assert_eq!(ours, expected, "{label}");

            if label.contains("compact") {
                assert!(
                    level_m(&payload) > ours,
                    "{label}: level M should need a bigger grid than the spec size {expected}"
                );
            }
        }
    }

    #[test]
    fn every_module_appears_in_exactly_one_block() {
        for (label, payload, _) in cases() {
            let grid = Grid::build(&payload).unwrap();
            let width = grid.width();
            let mut seen = vec![0usize; width * width];

            for block in 0..grid.block_count() {
                let (row0, col0) = grid.block_origin(block);
                for (i, cell) in grid.block_cells(block).iter().enumerate() {
                    let row = row0 + i / BLOCK;
                    let col = col0 + i % BLOCK;
                    if row >= width || col >= width {
                        assert_eq!(*cell, Cell::Outside, "{label} block {block} cell {i}");
                        continue;
                    }
                    seen[row * width + col] += 1;
                }
            }

            assert!(seen.iter().all(|n| *n == 1), "{label}: every module covered exactly once");
        }
    }

    #[test]
    fn cells_report_the_right_colour() {
        for (label, payload, _) in cases() {
            let grid = Grid::build(&payload).unwrap();
            for block in 0..grid.block_count() {
                let (row0, col0) = grid.block_origin(block);
                for (i, cell) in grid.block_cells(block).iter().enumerate() {
                    let row = row0 + i / BLOCK;
                    let col = col0 + i % BLOCK;
                    let expected = if row >= grid.width() || col >= grid.width() {
                        Cell::Outside
                    } else if grid.is_dark(row, col) {
                        Cell::Dark
                    } else {
                        Cell::Light
                    };
                    assert_eq!(*cell, expected, "{label} block {block} cell {i}");
                }
            }
        }
    }

    #[test]
    fn blocks_are_always_a_full_square_of_cells() {
        for (label, payload, _) in cases() {
            let grid = Grid::build(&payload).unwrap();
            for block in 0..grid.block_count() {
                assert_eq!(grid.block_cells(block).len(), BLOCK * BLOCK, "{label} block {block}");
            }
        }
    }

    #[test]
    fn extents_stay_inside_the_code_and_are_one_based() {
        for (label, payload, width) in cases() {
            let grid = Grid::build(&payload).unwrap();
            let last = grid.block_count() - 1;

            let (r0, r1, c0, c1) = grid.block_extent(0);
            assert_eq!((r0, c0), (1, 1), "{label} first block starts at 1,1");
            assert_eq!((r1, c1), (BLOCK, BLOCK), "{label} first block ends at the block size");

            let (_, r1, _, c1) = grid.block_extent(last);
            assert_eq!((r1, c1), (width, width), "{label} last block ends at the code edge");
        }
    }

    #[test]
    fn out_of_range_reads_are_light_rather_than_a_panic() {
        let grid = Grid::build(&standard(&mnemonic(V12))).unwrap();
        assert!(!grid.is_dark(grid.width(), 0));
        assert!(!grid.is_dark(0, grid.width()));
        assert!(!grid.is_dark(usize::MAX, usize::MAX));
    }

    #[test]
    fn an_empty_payload_is_an_error_not_a_panic() {
        // A zero length payload is not something the app should ever produce,
        // but it must not take the process down if it does.
        let _ = Grid::build(&[]);
    }
}
