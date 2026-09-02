// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

mod app;
mod seedqr;
mod theme;

use slint_keyos_platform::app_ui2;

app_ui2!("Seed XOR");

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);
    app::init(&ui);

    ui.run().expect("UI running");
}
