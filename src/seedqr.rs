// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// Rendering for the transcription screens. The grid geometry and the SeedQR
// encoding rules live in `seed-core`, which has no KeyOS dependency and is
// covered by `cargo test -p seed-core`.

use seed_core::seedqr::{Cell, Grid, BLOCK};
use slint_keyos_platform::slint::{Image, Rgba8Pixel, SharedPixelBuffer};

const HIGHLIGHT: [u8; 3] = [0xf7, 0x9a, 0x23];

/// Build the code for a seed, using the SDK's own SeedQR payload encoders.
pub fn encode(seed: &security::Seed, compact: bool) -> Result<Grid, String> {
    let payload = if compact { seed.to_compact_seed_qr_data() } else { seed.to_standard_seed_qr_data() }
        .map_err(|e| format!("Could not build the code: {e}"))?;

    Grid::build(&payload).map_err(|e| e.to_string())
}

pub fn cells_as_i32(grid: &Grid, index: usize) -> Vec<i32> {
    grid.block_cells(index).into_iter().map(Cell::as_i32).collect()
}

/// The whole code at a whole-pixel scale, so no module is blurred by resampling.
pub fn render_full(grid: &Grid, target_px: usize) -> Image {
    let scale = (target_px / grid.width()).max(1);
    draw(grid, scale, None)
}

/// The whole code with the active block outlined, for the corner mini-map.
pub fn render_minimap(grid: &Grid, block_index: usize, target_px: usize) -> Image {
    let scale = (target_px / grid.width()).max(2);
    draw(grid, scale, Some(block_index))
}

fn draw(grid: &Grid, scale: usize, highlight: Option<usize>) -> Image {
    let side = grid.width() * scale;
    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(side as u32, side as u32);
    let pixels = buffer.make_mut_slice();

    for px in pixels.iter_mut() {
        *px = Rgba8Pixel { r: 0xff, g: 0xff, b: 0xff, a: 0xff };
    }

    for row in 0..grid.width() {
        for col in 0..grid.width() {
            if grid.is_dark(row, col) {
                fill(pixels, side, col * scale, row * scale, scale, scale, [0, 0, 0]);
            }
        }
    }

    if let Some(index) = highlight {
        let (row0, col0) = grid.block_origin(index);
        let x = col0 * scale;
        let y = row0 * scale;
        let w = (BLOCK * scale).min(side.saturating_sub(x));
        let h = (BLOCK * scale).min(side.saturating_sub(y));
        let thickness = scale.max(2);

        fill(pixels, side, x, y, w, thickness, HIGHLIGHT);
        fill(pixels, side, x, y + h.saturating_sub(thickness), w, thickness, HIGHLIGHT);
        fill(pixels, side, x, y, thickness, h, HIGHLIGHT);
        fill(pixels, side, x + w.saturating_sub(thickness), y, thickness, h, HIGHLIGHT);
    }

    Image::from_rgba8(buffer)
}

fn fill(pixels: &mut [Rgba8Pixel], stride: usize, x: usize, y: usize, w: usize, h: usize, rgb: [u8; 3]) {
    for dy in 0..h {
        let row = y + dy;
        if row >= stride {
            break;
        }
        for dx in 0..w {
            let col = x + dx;
            if col >= stride {
                break;
            }
            pixels[row * stride + col] = Rgba8Pixel { r: rgb[0], g: rgb[1], b: rgb[2], a: 0xff };
        }
    }
}
