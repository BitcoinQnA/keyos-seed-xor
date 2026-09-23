#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p target/warning-previews

viewer=(foundation-slint-viewer tests/warnings.slint
    -L ui=ui/ui
    -L theme=ui/ui)
"${viewer[@]}" --check
parts_viewer=(foundation-slint-viewer tests/parts.slint -L ui=ui/ui -L theme=ui/ui)
"${parts_viewer[@]}" --check

for height in 760 800; do
    for dark in false true; do
        for parts in 2 3 4; do
            printf '{"window-height":%s,"dark":%s,"parts":%s}' "$height" "$dark" "$parts" |
                "${viewer[@]}" --load-data - --screenshot \
                    "target/warning-previews/risks-${parts}-${height}-dark-${dark}.png"
            for splitting in false true; do
                printf '{"window-height":%s,"dark":%s,"parts":%s,"counting":true,"splitting":%s}' \
                    "$height" "$dark" "$parts" "$splitting" |
                    "${viewer[@]}" --load-data - --screenshot \
                        "target/warning-previews/count-${parts}-${height}-dark-${dark}-split-${splitting}.png"
            done
        done
        printf '{"window-height":%s,"dark":%s,"confirmation":true}' "$height" "$dark" |
            "${viewer[@]}" --load-data - --screenshot \
                "target/warning-previews/backups-${height}-dark-${dark}.png"
        printf '{"window-height":%s,"dark":%s,"confirmation":true,"error":"Could not split that seed. Please try again."}' "$height" "$dark" |
            "${viewer[@]}" --load-data - --screenshot \
                "target/warning-previews/error-${height}-dark-${dark}.png"
        printf '{"window-height":%s,"dark":%s,"confirmation":true,"checksum":true}' "$height" "$dark" |
            "${parts_viewer[@]}" --load-data - --screenshot \
                "target/warning-previews/parts-finish-${height}-dark-${dark}.png"
        printf '{"window-height":%s,"dark":%s,"confirmation":false,"checksum":true}' "$height" "$dark" |
            "${parts_viewer[@]}" --load-data - --screenshot \
                "target/warning-previews/parts-list-${height}-dark-${dark}.png"
    done
done
