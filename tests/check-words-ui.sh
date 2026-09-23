#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p target/word-previews

viewer=(foundation-slint-viewer tests/words.slint -L ui=ui/ui -L theme=ui/ui)
"${viewer[@]}" --check

for height in 760 800; do
    for dark in false true; do
        for splitting in false true; do
            for second_page in false true; do
                printf '{"window-height":%s,"dark":%s,"splitting":%s,"second-page":%s}' \
                    "$height" "$dark" "$splitting" "$second_page" |
                    "${viewer[@]}" --load-data - --screenshot \
                        "target/word-previews/words-${height}-dark-${dark}-split-${splitting}-page2-${second_page}.png"
            done
        done
    done
done
