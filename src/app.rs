// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// App state and the Slint callback wiring.
//
// Everything the user loads lives in this struct and nowhere else. There is no
// filesystem write permission in the manifest, so it cannot be persisted even by
// accident; `clear` scrubs the typed words, `bip39::Mnemonic` is built with the
// `zeroize` feature so every seed and every part scrubs itself when dropped, and
// `security::Seed` does the same.

use std::{cell::RefCell, rc::Rc};

use bip39::{Language, Mnemonic};
use slint_keyos_platform::{
    gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult},
    navigation::open_qr_scanner,
    slint::{ComponentHandle, ModelRc, SharedString, VecModel},
};
use zeroize::{Zeroize, Zeroizing};

use seed_core::{
    seedqr::BLOCK,
    xor::{self, XorError},
};

use crate::{
    entropy::draw_entropy, gui_permissions::GuiPermissions, seed_input, seedqr, Actions, AppWindow,
    SeedState,
};

const MAX_SUGGESTIONS: usize = 3;
/// Two columns of six, like the firmware seed word view.
const PER_PAGE: usize = 12;
const PREVIEW_PX: usize = 416;
const MINIMAP_PX: usize = 88;

/// A part that duplicates another cannot be split into, and `xor::split` says so
/// rather than handing back a set that will not recombine. With 128 bits of
/// entropy a collision will not happen, but retrying costs nothing and turns an
/// impossible dead end into a non-event.
const SPLIT_ATTEMPTS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Mode {
    #[default]
    Split,
    Combine,
}

/// What the load pages should do once a seed is in.
mod after_load {
    /// Another part is still outstanding.
    pub const LOAD_ANOTHER: i32 = 0;
    /// The source is in; choose how many parts to split it into.
    pub const CHOOSE_COUNT: i32 = 1;
    /// Everything is in; show the seed.
    pub const SHOW_SEED: i32 = 2;
}

#[derive(Default)]
pub struct AppState {
    mode: Mode,
    /// How many parts, 2 to 4.
    part_count: usize,

    /// Words being typed in. Scrubbed on reset.
    words: Vec<String>,
    /// Set when the user taps a word to correct it, so entry returns to that
    /// slot instead of the first empty one.
    pinned_slot: Option<usize>,
    review_page: usize,

    /// Split: the seed being split, and the parts it was split into.
    source: Option<Mnemonic>,
    parts: Vec<Mnemonic>,
    show_checksum: bool,

    /// Combine: the parts entered so far.
    collected: Vec<Mnemonic>,

    /// The seed currently on the viewer page, and the same value as a
    /// `security::Seed` for the transcription flow.
    viewing: Option<Mnemonic>,
    view_label: String,
    view_page: usize,
    seed: Option<security::Seed>,

    grid: Option<seed_core::seedqr::Grid>,
    compact: bool,
    block_index: usize,
}

impl AppState {
    fn word_count(&self) -> usize {
        if self.words.is_empty() {
            12
        } else {
            self.words.len()
        }
    }

    /// Every part of a set has to be the same length, so once the first one is
    /// in, the choice is made.
    fn locked_word_count(&self) -> Option<usize> {
        self.collected.first().map(|m| m.word_count())
    }

    fn active_slot(&self) -> usize {
        self.pinned_slot
            .filter(|slot| *slot < self.words.len())
            .or_else(|| self.words.iter().position(|w| w.is_empty()))
            .unwrap_or(self.words.len().saturating_sub(1))
    }

    fn words_entered(&self) -> usize {
        self.words.iter().filter(|w| !w.is_empty()).count()
    }

    fn complete(&self) -> bool {
        !self.words.is_empty() && self.words.iter().all(|w| !w.is_empty())
    }

    /// Scrub the words being typed, without touching anything already loaded.
    fn clear_entry(&mut self) {
        self.words.zeroize();
        self.words.clear();
        self.pinned_slot = None;
        self.review_page = 0;
    }

    fn clear(&mut self) {
        self.clear_entry();
        self.part_count = 2;
        // Mnemonic is built with bip39's `zeroize` feature, so dropping these
        // scrubs them.
        self.source = None;
        self.parts.clear();
        self.collected.clear();
        self.viewing = None;
        self.view_label.clear();
        self.view_page = 0;
        self.show_checksum = false;
        self.seed = None;
        self.grid = None;
        self.compact = false;
        self.block_index = 0;
    }
}

pub fn init(ui: &AppWindow) {
    let state = Rc::new(RefCell::new(AppState::default()));
    {
        let mut current = state.borrow_mut();
        current.part_count = 2;
        current.words = vec![String::new(); 12];
    }
    push_entry(ui, &state.borrow());
    push_parts(ui, &state.borrow());

    let actions = ui.global::<Actions>();

    // ---- Flow selection ----

    actions.on_start_split({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                current.clear();
                current.mode = Mode::Split;
                current.words = vec![String::new(); 12];
            }
            clear_messages(&ui);
            ui.global::<SeedState>().set_splitting(true);
            push_load_prompt(&ui, &state.borrow());
            push_entry(&ui, &state.borrow());
            push_parts(&ui, &state.borrow());
        }
    });

    actions.on_start_combine({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                current.clear();
                current.mode = Mode::Combine;
                current.words = vec![String::new(); 12];
            }
            clear_messages(&ui);
            ui.global::<SeedState>().set_splitting(false);
            push_load_prompt(&ui, &state.borrow());
            push_entry(&ui, &state.borrow());
            push_parts(&ui, &state.borrow());
        }
    });

    actions.on_set_part_count({
        let ui = ui.as_weak();
        let state = state.clone();
        move |count| {
            let Some(ui) = ui.upgrade() else { return };
            let count = (count.max(xor::MIN_PARTS as i32) as usize).min(xor::MAX_PARTS);
            state.borrow_mut().part_count = count;
            push_load_prompt(&ui, &state.borrow());
            push_parts(&ui, &state.borrow());
        }
    });

    // ---- Split ----

    actions.on_do_split({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };

            let (source, count) = {
                let current = state.borrow();
                let Some(source) = current.source.clone() else {
                    return fail(&ui, "Load a seed first.");
                };
                (source, current.part_count)
            };

            let Some(len) = xor::entropy_len(source.word_count()) else {
                return fail(&ui, "Seed XOR takes 12 or 24 word seeds.");
            };

            let mut parts = None;
            let mut last_error = String::new();
            for _ in 0..SPLIT_ATTEMPTS {
                let mut entropy = Zeroizing::new(Vec::with_capacity(count - 1));
                for _ in 0..count - 1 {
                    match draw_entropy(len) {
                        Ok(bytes) => entropy.push(bytes),
                        Err(message) => return fail(&ui, &message),
                    }
                }

                match xor::split(&source, count, &entropy) {
                    Ok(made) => {
                        parts = Some(made);
                        break;
                    }
                    // The only retryable case. Everything else is a real bug and
                    // retrying would just hide it.
                    Err(XorError::DuplicateParts) => {
                        last_error = XorError::DuplicateParts.to_string();
                    }
                    Err(e) => {
                        return fail(&ui, &e.to_string());
                    }
                }
            }

            let Some(parts) = parts else {
                return fail(&ui, &format!("Could not split that seed: {last_error}"));
            };

            state.borrow_mut().parts = parts;
            clear_messages(&ui);
            push_parts(&ui, &state.borrow());
            true
        }
    });

    actions.on_toggle_checksum({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                current.show_checksum = !current.show_checksum;
            }
            push_parts(&ui, &state.borrow());
        }
    });

    // ---- Loading a seed ----

    actions.on_load_scan({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };
            let Some(data) = scan("Scan a SeedQR") else { return false };

            match seed_input::parse_seedqr(&data) {
                Ok(mnemonic) => match take_loaded(&ui, &state, mnemonic) {
                    Ok(()) => true,
                    Err(message) => fail(&ui, &message),
                },
                Err(message) => fail(&ui, &message),
            }
        }
    });

    actions.on_begin_entry({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                let count = current.locked_word_count().unwrap_or(12);
                current.clear_entry();
                current.words = vec![String::new(); count];
            }
            clear_messages(&ui);
            push_entry(&ui, &state.borrow());
        }
    });

    // Backing out of word entry throws away what was typed, and nothing else.
    // A half-entered part must not take the parts already collected with it.
    actions.on_cancel_entry({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                let count = current.locked_word_count().unwrap_or(12);
                current.clear_entry();
                current.words = vec![String::new(); count];
            }
            clear_messages(&ui);
            push_entry(&ui, &state.borrow());
        }
    });

    // ---- Word entry ----

    actions.on_set_word_count({
        let ui = ui.as_weak();
        let state = state.clone();
        move |count| {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                // Locked once a part is in: mixing lengths is refused later
                // anyway, so it is not offered here.
                if current.locked_word_count().is_some() {
                    return;
                }
                let count = if count == 24 { 24 } else { 12 };
                current.clear_entry();
                current.words = vec![String::new(); count];
            }
            clear_messages(&ui);
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
                let mut current = state.borrow_mut();
                let slot = current.active_slot();
                if let Some(entry) = current.words.get_mut(slot) {
                    *entry = word.to_string();
                }
                current.pinned_slot = None;
            }
            clear_messages(&ui);
            push_entry(&ui, &state.borrow());
        }
    });

    actions.on_remove_last_word({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                current.pinned_slot = None;
                if let Some(slot) = current.words.iter().rposition(|w| !w.is_empty()) {
                    current.words[slot].zeroize();
                    current.words[slot] = String::new();
                }
            }
            clear_messages(&ui);
            push_entry(&ui, &state.borrow());
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
            clear_messages(&ui);
            push_entry(&ui, &state.borrow());
        }
    });

    actions.on_commit_words({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };
            let phrase = state.borrow().words.join(" ");

            let mnemonic = match Mnemonic::parse_in_normalized(Language::English, &phrase) {
                Ok(mnemonic) => mnemonic,
                Err(_) => {
                    return fail(
                        &ui,
                        "Those words are not a valid seed. Check the last word, then check the rest.",
                    )
                }
            };

            match take_loaded(&ui, &state, mnemonic) {
                Ok(()) => {
                    state.borrow_mut().clear_entry();
                    true
                }
                Err(message) => fail(&ui, &message),
            }
        }
    });

    actions.on_review_next_page({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                let pages = current.words.len().div_ceil(PER_PAGE);
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
            let page = state.borrow().review_page.saturating_sub(1);
            state.borrow_mut().review_page = page;
            push_entry(&ui, &state.borrow());
        }
    });

    // ---- Viewing a seed ----

    actions.on_view_part({
        let ui = ui.as_weak();
        let state = state.clone();
        move |index| {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                let index = index.max(0) as usize;
                let Some(part) = current.parts.get(index).cloned() else { return };
                let count = current.part_count;
                current.viewing = Some(part);
                current.view_label = format!("Part {} of {}", index + 1, count);
                current.view_page = 0;
            }
            push_view(&ui, &state.borrow());
        }
    });

    actions.on_view_next_page({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            {
                let mut current = state.borrow_mut();
                let words = current.viewing.as_ref().map(|m| m.word_count()).unwrap_or(0);
                if current.view_page + 1 < words.div_ceil(PER_PAGE) {
                    current.view_page += 1;
                }
            }
            push_view(&ui, &state.borrow());
        }
    });

    actions.on_view_prev_page({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            let page = state.borrow().view_page.saturating_sub(1);
            state.borrow_mut().view_page = page;
            push_view(&ui, &state.borrow());
        }
    });

    // Hand whatever is on the viewer to the transcription flow.
    actions.on_transcribe_view({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };
            let (mnemonic, label) = {
                let current = state.borrow();
                let Some(mnemonic) = current.viewing.clone() else {
                    return fail(&ui, "Nothing to transcribe.");
                };
                (mnemonic, current.view_label.clone())
            };

            let seed = match seed_input::to_sdk_seed(&mnemonic) {
                Ok(seed) => seed,
                Err(message) => return fail(&ui, &message),
            };
            state.borrow_mut().seed = Some(seed);
            push_seed(&ui, &state.borrow(), &label);
            clear_messages(&ui);
            true
        }
    });

    // ---- Transcription ----

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
                Err(message) => fail(&ui, &message),
            }
        }
    });

    actions.on_next_block({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return false };
            let moved = {
                let mut current = state.borrow_mut();
                let last =
                    current.grid.as_ref().map(|g| g.block_count()).unwrap_or(0).saturating_sub(1);
                if current.block_index < last {
                    current.block_index += 1;
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
                let mut current = state.borrow_mut();
                current.block_index = current.block_index.saturating_sub(1);
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
            match seed_input::parse_seedqr(&data)
                .and_then(|scanned| seed_input::to_sdk_seed(&scanned))
            {
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
                            "It decodes to the same words shown on the previous screen. Store it somewhere only you can reach.".into(),
                        );
                    } else {
                        seed_state.set_verify_ok(false);
                        seed_state.set_verify_title("That is a different seed".into());
                        seed_state.set_verify_detail(
                            "The code scanned cleanly but it is not the one you were copying. Compare your copy against the grid again.".into(),
                        );
                    }
                }
                Err(message) => {
                    seed_state.set_verify_ok(false);
                    // TODO: localize
                    seed_state.set_verify_title("Cannot verify this code".into());
                    seed_state.set_verify_detail(message.into());
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
                let mut current = state.borrow_mut();
                current.clear();
                current.words = vec![String::new(); 12];
            }
            let seed_state = ui.global::<SeedState>();
            clear_messages(&ui);
            seed_state.set_words_entered(0);
            seed_state.set_word_count_locked(false);
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
            push_parts(&ui, &state.borrow());
            push_view(&ui, &state.borrow());
        }
    });
}

/// File a loaded seed where the current flow needs it, and say what happens next.
///
/// The split flow takes one seed and moves on to the part count. The combine
/// flow takes them one at a time and folds them together once the last one is
/// in.
fn take_loaded(ui: &AppWindow, state: &Rc<RefCell<AppState>>, mnemonic: Mnemonic) -> Result<(), String> {
    seed_input::ensure_supported(&mnemonic)?;
    let seed_state = ui.global::<SeedState>();
    let mode = state.borrow().mode;

    match mode {
        Mode::Split => {
            state.borrow_mut().source = Some(mnemonic);
            clear_messages(ui);
            seed_state.set_after_load(after_load::CHOOSE_COUNT);
            push_load_prompt(ui, &state.borrow());
            Ok(())
        }
        Mode::Combine => {
            {
                let current = state.borrow();
                if let Some(expected) = current.locked_word_count() {
                    if mnemonic.word_count() != expected {
                        return Err(format!(
                            "Part 1 has {expected} words and this one has {}. Every part of a set is the same length.",
                            mnemonic.word_count()
                        ));
                    }
                }
                if current.collected.contains(&mnemonic) {
                    return Err(
                        "That is a part you have already entered. Each part is used once: entering one twice cancels it out and gives a different seed."
                            .to_string(),
                    );
                }
            }

            state.borrow_mut().collected.push(mnemonic);

            let done = {
                let current = state.borrow();
                current.collected.len() >= current.part_count
            };

            if !done {
                clear_messages(ui);
                seed_state.set_after_load(after_load::LOAD_ANOTHER);
                push_load_prompt(ui, &state.borrow());
                push_entry(ui, &state.borrow());
                return Ok(());
            }

            let combined = {
                let current = state.borrow();
                xor::combine(&current.collected).map_err(|e| e.to_string())?
            };

            {
                let mut current = state.borrow_mut();
                let count = current.part_count;
                current.view_label = format!("Combined from {count} parts");
                current.viewing = Some(combined);
                current.view_page = 0;
            }
            clear_messages(ui);
            seed_state.set_after_load(after_load::SHOW_SEED);
            push_view(ui, &state.borrow());
            Ok(())
        }
    }
}

/// Show a message on the current page and keep it there.
fn fail(ui: &AppWindow, message: &str) -> bool {
    ui.global::<SeedState>().set_entry_error(message.into());
    false
}

fn clear_messages(ui: &AppWindow) {
    let seed_state = ui.global::<SeedState>();
    seed_state.set_entry_text(SharedString::new());
    seed_state.set_entry_error(SharedString::new());
    seed_state.set_suggestions(ModelRc::new(VecModel::<SharedString>::default()));
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
        _ => None,
    }
}

/// Split a word list into the firmware's two columns of six, for one page.
fn columns(words: &[SharedString], page: usize) -> (Vec<SharedString>, Vec<SharedString>, usize, usize, usize) {
    let count = words.len();
    let pages = count.div_ceil(PER_PAGE).max(1);
    let page = page.min(pages - 1);
    let start = page * PER_PAGE;
    let end = (start + PER_PAGE).min(count);
    let column = (end - start).div_ceil(2);

    (
        words[start..start + column].to_vec(),
        words[start + column..end].to_vec(),
        start,
        start + column,
        pages,
    )
}

fn push_load_prompt(ui: &AppWindow, state: &AppState) {
    let seed_state = ui.global::<SeedState>();

    let (title, hint) = match state.mode {
        Mode::Split => (
            "Load the seed to split".to_string(),
            "This is the seed the parts will rebuild. It is held in memory only while the app is open.".to_string(),
        ),
        Mode::Combine => {
            let next = state.collected.len() + 1;
            let count = state.part_count;
            (
                format!("Load part {next} of {count}"),
                if next == 1 {
                    "The order you enter the parts in does not matter.".to_string()
                } else {
                    format!("{} in, {} to go.", state.collected.len(), count - state.collected.len())
                },
            )
        }
    };

    seed_state.set_load_title(title.into());
    seed_state.set_load_hint(hint.into());
    seed_state.set_part_count(state.part_count as i32);
    seed_state.set_word_count_locked(state.locked_word_count().is_some());
}

fn push_entry(ui: &AppWindow, state: &AppState) {
    let seed_state = ui.global::<SeedState>();
    let count = state.word_count();

    seed_state.set_word_count(count as i32);
    seed_state.set_word_count_locked(state.locked_word_count().is_some());
    seed_state.set_active_slot(state.active_slot() as i32);
    seed_state.set_words_entered(state.words_entered() as i32);
    seed_state.set_entry_complete(state.complete());

    let all: Vec<SharedString> = state
        .words
        .iter()
        .map(|w| SharedString::from(if w.is_empty() { "\u{2014}" } else { w.as_str() }))
        .collect();

    // Entry page: the whole list, so earlier words can be scrolled back to.
    seed_state.set_all_words(ModelRc::new(VecModel::from(all.clone())));

    // Review page: two columns of six, paginated the way the firmware does it.
    let (left, right, left_offset, right_offset, pages) = columns(&all, state.review_page);
    seed_state.set_review_page(state.review_page.min(pages - 1) as i32);
    seed_state.set_review_page_count(pages as i32);
    seed_state.set_left_offset(left_offset as i32);
    seed_state.set_right_offset(right_offset as i32);
    seed_state.set_review_left(ModelRc::new(VecModel::from(left)));
    seed_state.set_review_right(ModelRc::new(VecModel::from(right)));
}

fn push_parts(ui: &AppWindow, state: &AppState) {
    let seed_state = ui.global::<SeedState>();
    let count = state.part_count;

    let labels: Vec<SharedString> = (0..state.parts.len())
        .map(|i| SharedString::from(format!("Part {} of {}", i + 1, count)))
        .collect();
    seed_state.set_part_labels(ModelRc::new(VecModel::from(labels)));
    seed_state.set_part_count(count as i32);

    let words = state.source.as_ref().map(|m| m.word_count()).unwrap_or(0);
    seed_state.set_parts_summary(
        format!("{count} parts of {words} words. All {count} are needed to rebuild the seed.").into(),
    );

    seed_state.set_show_checksum(state.show_checksum);
    seed_state.set_checksum_word(match (state.show_checksum, state.source.as_ref()) {
        (true, Some(seed)) => xor::checksum_word(seed).into(),
        _ => SharedString::new(),
    });
}

fn push_view(ui: &AppWindow, state: &AppState) {
    let seed_state = ui.global::<SeedState>();
    let Some(mnemonic) = state.viewing.as_ref() else {
        seed_state.set_view_left(ModelRc::new(VecModel::<SharedString>::default()));
        seed_state.set_view_right(ModelRc::new(VecModel::<SharedString>::default()));
        return;
    };

    let words: Vec<SharedString> = mnemonic.words().map(SharedString::from).collect();
    let (left, right, left_offset, right_offset, pages) = columns(&words, state.view_page);

    seed_state.set_view_title(state.view_label.as_str().into());
    seed_state.set_view_hint(match state.mode {
        Mode::Split => "Write these words down. This part is a valid seed on its own, and it is not the seed you loaded.",
        Mode::Combine => "This is the seed your parts rebuild. Nothing about the parts has changed.",
    }
    .into());
    seed_state.set_view_cta(match state.mode {
        Mode::Split => "Transcribe This Part",
        Mode::Combine => "Transcribe This Seed",
    }
    .into());

    seed_state.set_view_page(state.view_page.min(pages - 1) as i32);
    seed_state.set_view_page_count(pages as i32);
    seed_state.set_view_left_offset(left_offset as i32);
    seed_state.set_view_right_offset(right_offset as i32);
    seed_state.set_view_left(ModelRc::new(VecModel::from(left)));
    seed_state.set_view_right(ModelRc::new(VecModel::from(right)));
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
