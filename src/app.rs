// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// App state and the Slint callback wiring.
//
// Everything the user loads lives in this struct and nowhere else. There is no
// filesystem write permission in the manifest, so it cannot be persisted even
// by accident, and `reset` scrubs the words before the seed is dropped.

use std::{cell::RefCell, rc::Rc};

use bip39::{Language, Mnemonic};
use slint_keyos_platform::{
    gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult},
    navigation::open_qr_scanner,
    slint::{ComponentHandle, ModelRc, SharedString, VecModel},
};
use zeroize::Zeroize;

use seed_core::seedqr::BLOCK;

use crate::{gui_permissions::GuiPermissions, seedqr, Actions, AppWindow, SeedState};

const MAX_SUGGESTIONS: usize = 3;
/// Two columns of six, like the firmware seed word view.
const REVIEW_PER_PAGE: usize = 12;
const PREVIEW_PX: usize = 416;
const MINIMAP_PX: usize = 88;

#[derive(Default)]
pub struct AppState {
    /// Words being typed in. Scrubbed on reset.
    words: Vec<String>,
    /// Set when the user taps a word to correct it, so entry returns to that
    /// slot instead of the first empty one.
    pinned_slot: Option<usize>,
    /// The loaded seed. Zeroizes itself when dropped.
    seed: Option<security::Seed>,
    grid: Option<seed_core::seedqr::Grid>,
    compact: bool,
    block_index: usize,
    review_page: usize,
}

impl AppState {
    fn word_count(&self) -> usize {
        if self.words.is_empty() { 12 } else { self.words.len() }
    }

    fn active_slot(&self) -> usize {
        self.pinned_slot
            .filter(|slot| *slot < self.words.len())
            .or_else(|| self.words.iter().position(|w| w.is_empty()))
            .unwrap_or(self.words.len().saturating_sub(1))
    }

    fn words_entered(&self) -> usize { self.words.iter().filter(|w| !w.is_empty()).count() }

    fn complete(&self) -> bool {
        !self.words.is_empty() && self.words.iter().all(|w| !w.is_empty())
    }

    fn clear(&mut self) {
        self.words.zeroize();
        self.words.clear();
        self.pinned_slot = None;
        self.review_page = 0;
        self.seed = None;
        self.grid = None;
        self.compact = false;
        self.block_index = 0;
    }
}

pub fn init(ui: &AppWindow) {
    let state = Rc::new(RefCell::new(AppState::default()));
    state.borrow_mut().words = vec![String::new(); 12];

    push_entry(ui, &state.borrow());

    let actions = ui.global::<Actions>();

    actions.on_scan_seed({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };
            let Some(data) = scan("Scan a SeedQR") else { return false };

            match load_seed(&data) {
                Ok(seed) => {
                    {
                        let mut current = state.borrow_mut();
                        current.clear();
                        current.seed = Some(seed);
                    }
                    push_seed(&ui, &state.borrow(), "a scan");
                    ui.global::<SeedState>().set_entry_error(SharedString::new());
                    true
                }
                Err(message) => {
                    ui.global::<SeedState>().set_entry_error(message.into());
                    false
                }
            }
        }
    });

    actions.on_set_word_count({
        let ui = ui.as_weak();
        let state = state.clone();
        move |count| {
            let Some(ui) = ui.upgrade() else { return };
            let count = if count == 24 { 24 } else { 12 };
            {
                let mut current = state.borrow_mut();
                current.words.zeroize();
                current.words = vec![String::new(); count];
                current.pinned_slot = None;
                current.review_page = 0;
            }
            ui.global::<SeedState>().set_entry_text(SharedString::new());
            ui.global::<SeedState>().set_entry_error(SharedString::new());
            ui.global::<SeedState>().set_suggestions(ModelRc::new(VecModel::<SharedString>::default()));
            push_entry(&ui, &state.borrow());
        }
    });

    actions.on_entry_changed({
        let ui = ui.as_weak();
        move |text| {
            let Some(ui) = ui.upgrade() else { return };
            let prefix = text.trim().to_lowercase();
            let words: Vec<SharedString> = if prefix.is_empty() {
                Vec::new()
            } else {
                Language::English
                    .words_by_prefix(&prefix)
                    .iter()
                    .take(MAX_SUGGESTIONS)
                    .map(|w| SharedString::from(*w))
                    .collect()
            };
            ui.global::<SeedState>().set_suggestions(ModelRc::new(VecModel::from(words)));
        }
    });

    actions.on_accept_word({
        let ui = ui.as_weak();
        let state = state.clone();
        move |word| {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut state = state.borrow_mut();
                let slot = state.active_slot();
                if let Some(entry) = state.words.get_mut(slot) {
                    *entry = word.to_string();
                }
                state.pinned_slot = None;
            }
            let seed_state = ui.global::<SeedState>();
            seed_state.set_entry_text(SharedString::new());
            seed_state.set_entry_error(SharedString::new());
            seed_state.set_suggestions(ModelRc::new(VecModel::<SharedString>::default()));
            push_entry(&ui, &state.borrow());
        }
    });

    actions.on_remove_last_word({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut state = state.borrow_mut();
                state.pinned_slot = None;
                if let Some(slot) = state.words.iter().rposition(|w| !w.is_empty()) {
                    state.words[slot].zeroize();
                    state.words[slot] = String::new();
                }
            }
            let seed_state = ui.global::<SeedState>();
            seed_state.set_entry_text(SharedString::new());
            seed_state.set_entry_error(SharedString::new());
            seed_state.set_suggestions(ModelRc::new(VecModel::<SharedString>::default()));
            push_entry(&ui, &state.borrow());
        }
    });

    actions.on_commit_words({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };
            let phrase = state.borrow().words.join(" ");

            match Mnemonic::parse_in_normalized(Language::English, &phrase) {
                Ok(mnemonic) => {
                    let seed = security::Seed::from_mnemonic(&mnemonic);
                    state.borrow_mut().seed = Some(seed);
                    push_seed(&ui, &state.borrow(), "the words you entered");
                    ui.global::<SeedState>().set_entry_error(SharedString::new());
                    true
                }
                Err(_) => {
                    ui.global::<SeedState>()
                        .set_entry_error("Those words are not a valid seed. Check the last word, then check the rest.".into());
                    false
                }
            }
        }
    });

    actions.on_edit_word({
        let ui = ui.as_weak();
        let state = state.clone();
        move |index| {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                let index = index.max(0) as usize;
                if index < current.words.len() {
                    current.words[index].zeroize();
                    current.words[index] = String::new();
                    current.pinned_slot = Some(index);
                }
            }
            let seed_state = ui.global::<SeedState>();
            seed_state.set_entry_text(SharedString::new());
            seed_state.set_entry_error(SharedString::new());
            seed_state.set_suggestions(ModelRc::new(VecModel::<SharedString>::default()));
            push_entry(&ui, &state.borrow());
        }
    });

    actions.on_review_next_page({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                let pages = current.words.len().div_ceil(REVIEW_PER_PAGE);
                if current.review_page + 1 < pages {
                    current.review_page += 1;
                }
            }
            push_entry(&ui, &state.borrow());
        }
    });

    actions.on_review_prev_page({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            state.borrow_mut().review_page = state.borrow().review_page.saturating_sub(1);
            push_entry(&ui, &state.borrow());
        }
    });

    actions.on_choose_format({
        let ui = ui.as_weak();
        let state = state.clone();
        move |compact| {
            let Some(ui) = ui.upgrade() else { return false };
            let encoded = {
                let current = state.borrow();
                let Some(seed) = current.seed.as_ref() else { return false };
                seedqr::encode(seed, compact)
            };

            match encoded {
                Ok(grid) => {
                    {
                        let mut current = state.borrow_mut();
                        current.grid = Some(grid);
                        current.compact = compact;
                        current.block_index = 0;
                    }
                    push_grid(&ui, &state.borrow());
                    true
                }
                Err(message) => {
                    ui.global::<SeedState>().set_entry_error(message.into());
                    false
                }
            }
        }
    });

    actions.on_next_block({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };
            let moved = {
                let mut state = state.borrow_mut();
                let last = state.grid.as_ref().map(|g| g.block_count()).unwrap_or(0).saturating_sub(1);
                if state.block_index < last {
                    state.block_index += 1;
                    true
                } else {
                    false
                }
            };
            if moved {
                push_block(&ui, &state.borrow());
            }
            moved
        }
    });

    actions.on_prev_block({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut state = state.borrow_mut();
                state.block_index = state.block_index.saturating_sub(1);
            }
            push_block(&ui, &state.borrow());
        }
    });

    actions.on_restart_transcription({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            state.borrow_mut().block_index = 0;
            push_block(&ui, &state.borrow());
        }
    });

    actions.on_verify_scan({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };
            let Some(data) = scan("Scan your copy") else { return false };

            let seed_state = ui.global::<SeedState>();
            match load_seed(&data) {
                Ok(scanned) => {
                    let matches = state
                        .borrow()
                        .seed
                        .as_ref()
                        .map(|original| original.bytes() == scanned.bytes())
                        .unwrap_or(false);

                    if matches {
                        seed_state.set_verify_ok(true);
                        seed_state.set_verify_title("Your copy is correct".into());
                        seed_state.set_verify_detail(
                            "It decodes to the same seed you loaded. Store it somewhere only you can reach.".into(),
                        );
                    } else {
                        seed_state.set_verify_ok(false);
                        seed_state.set_verify_title("That is a different seed".into());
                        seed_state.set_verify_detail(
                            "The code scanned cleanly but it is not the seed you loaded. Compare your copy against the grid again.".into(),
                        );
                    }
                }
                Err(_) => {
                    seed_state.set_verify_ok(false);
                    seed_state.set_verify_title("That is not a SeedQR".into());
                    seed_state.set_verify_detail(
                        "It scanned, but not as a SeedQR. A misread square usually does this. Check your copy against the grid.".into(),
                    );
                }
            }
            true
        }
    });

    actions.on_skip_verify({
        let ui = ui.as_weak();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            let seed_state = ui.global::<SeedState>();
            seed_state.set_verify_ok(false);
            seed_state.set_verify_title("Not checked".into());
            seed_state.set_verify_detail(
                "You skipped the check, so nothing here says your copy is right. Scanning it back is the only way to know.".into(),
            );
        }
    });

    actions.on_reset({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut state = state.borrow_mut();
                state.clear();
                state.words = vec![String::new(); 12];
            }
            let seed_state = ui.global::<SeedState>();
            seed_state.set_entry_text(SharedString::new());
            seed_state.set_entry_error(SharedString::new());
            seed_state.set_suggestions(ModelRc::new(VecModel::<SharedString>::default()));
            seed_state.set_words_entered(0);
            seed_state.set_loaded(false);
            seed_state.set_seed_word_count(0);
            seed_state.set_source_label(SharedString::new());
            seed_state.set_qr_width(0);
            seed_state.set_block_count(0);
            seed_state.set_block_cells(ModelRc::new(VecModel::<i32>::default()));
            seed_state.set_verify_title(SharedString::new());
            seed_state.set_verify_detail(SharedString::new());
            seed_state.set_verify_ok(false);
            push_entry(&ui, &state.borrow());
        }
    });
}

/// Open the system QR scanner. Returns the payload, or None if the user backed out.
fn scan(title: &str) -> Option<Vec<u8>> {
    let result = open_qr_scanner::<GuiPermissions>(ScanQrOptions {
        header_title: title.to_string(),
        ..ScanQrOptions::default()
    })
    .inspect_err(|e| log::error!("could not open the qr scanner: {e}"))
    .ok()??;

    match result {
        ScanQrResult::Qr { data, .. } => Some(data),
        ScanQrResult::Ur2 { .. } => None,
        _ => None,
    }
}

/// Parse a scan as a SeedQR. Only 12 and 24 word seeds have a SeedQR form, so
/// anything else is rejected here instead of panicking further in.
fn load_seed(data: &[u8]) -> Result<security::Seed, String> {
    let mnemonic = security::parse_seedqr(data)
        .map_err(|_| "That is not a SeedQR. Scan a Standard or Compact SeedQR.".to_string())?;

    match mnemonic.word_count() {
        12 | 24 => Ok(security::Seed::from_mnemonic(&mnemonic)),
        other => Err(format!("That is a {other} word seed. SeedQR only covers 12 and 24 word seeds.")),
    }
}

fn push_entry(ui: &AppWindow, state: &AppState) {
    let seed_state = ui.global::<SeedState>();
    let count = state.word_count();
    let entered = state.words_entered();
    let active = state.active_slot();

    seed_state.set_word_count(count as i32);
    seed_state.set_active_slot(active as i32);
    seed_state.set_words_entered(entered as i32);
    seed_state.set_entry_complete(state.complete());

    // Entry page: the whole list, so earlier words can be scrolled back to.
    let all: Vec<SharedString> = state
        .words
        .iter()
        .map(|w| SharedString::from(if w.is_empty() { "\u{2014}" } else { w.as_str() }))
        .collect();
    seed_state.set_all_words(ModelRc::new(VecModel::from(all)));

    // Review page: two columns of six, paginated the way the firmware does it.
    let pages = count.div_ceil(REVIEW_PER_PAGE).max(1);
    let page = state.review_page.min(pages - 1);
    let page_start = page * REVIEW_PER_PAGE;
    let page_end = (page_start + REVIEW_PER_PAGE).min(count);
    let column = (page_end - page_start).div_ceil(2);

    let as_model = |range: std::ops::Range<usize>| {
        let items: Vec<SharedString> = state.words[range]
            .iter()
            .map(|w| SharedString::from(if w.is_empty() { "\u{2014}" } else { w.as_str() }))
            .collect();
        ModelRc::new(VecModel::from(items))
    };

    seed_state.set_review_page(page as i32);
    seed_state.set_review_page_count(pages as i32);
    seed_state.set_left_offset(page_start as i32);
    seed_state.set_right_offset((page_start + column) as i32);
    seed_state.set_review_left(as_model(page_start..page_start + column));
    seed_state.set_review_right(as_model(page_start + column..page_end));
}

fn push_seed(ui: &AppWindow, state: &AppState, source: &str) {
    let seed_state = ui.global::<SeedState>();
    let Some(seed) = state.seed.as_ref() else { return };
    let words = seed.bytes().len() * 3 / 4;

    seed_state.set_loaded(true);
    seed_state.set_seed_word_count(words as i32);
    seed_state.set_source_label(source.into());
    seed_state.set_standard_label(format!("{0} by {0} grid", if words == 12 { 25 } else { 29 }).into());
    seed_state.set_compact_label(format!("{0} by {0} grid", if words == 12 { 21 } else { 25 }).into());
}

fn push_grid(ui: &AppWindow, state: &AppState) {
    let seed_state = ui.global::<SeedState>();
    let Some(grid) = state.grid.as_ref() else { return };

    seed_state.set_format_label(
        format!("{} SeedQR", if state.compact { "Compact" } else { "Standard" }).into(),
    );
    seed_state.set_qr_width(grid.width() as i32);
    seed_state.set_block_size(BLOCK as i32);
    seed_state.set_block_count(grid.block_count() as i32);
    seed_state.set_qr_preview(seedqr::render_full(grid, PREVIEW_PX));
    push_block(ui, state);
}

fn push_block(ui: &AppWindow, state: &AppState) {
    let seed_state = ui.global::<SeedState>();
    let Some(grid) = state.grid.as_ref() else { return };

    let index = state.block_index;
    let count = grid.block_count();
    let (row_from, row_to, col_from, col_to) = grid.block_extent(index);

    seed_state.set_block_index(index as i32);
    seed_state.set_last_block(index + 1 >= count);
    seed_state.set_block_label(format!("Block {} of {}", index + 1, count).into());
    seed_state.set_block_range(
        format!("Rows {row_from}-{row_to}, columns {col_from}-{col_to}").into(),
    );
    seed_state.set_block_cells(ModelRc::new(VecModel::from(seedqr::cells_as_i32(grid, index))));
    seed_state.set_minimap(seedqr::render_minimap(grid, index, MINIMAP_PX));
}
