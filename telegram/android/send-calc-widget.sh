#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONFIG=${WIDGET_BOT_CONFIG:-"$HOME/.config/widget-sandbox/telegram-live-test.env"}
HTML="$ROOT/poc.html"
EXPECTED_SHA256=6630b003766baed1fa86cea880d22e41dc416f63d800de3246941ede2396ad48

case "${1:-}" in
    "") DRY_RUN=0 ;;
    --dry-run) DRY_RUN=1 ;;
    *)
        printf 'usage: %s [--dry-run]\n' "$0" >&2
        exit 2
        ;;
esac
if [ "$#" -gt 1 ]; then
    printf 'usage: %s [--dry-run]\n' "$0" >&2
    exit 2
fi

ACTUAL_SHA256=$(shasum -a 256 "$HTML" | cut -d ' ' -f 1)
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    printf 'payload SHA-256 mismatch: expected %s, got %s\n' \
        "$EXPECTED_SHA256" "$ACTUAL_SHA256" >&2
    exit 1
fi

cd "$ROOT"
python3 tools/send_widget.py inspect --html "$HTML"

if [ "$DRY_RUN" -eq 1 ]; then
    exit 0
fi
if [ ! -f "$CONFIG" ]; then
    printf '%s\n' "missing bot token/chat config: $CONFIG" >&2
    exit 1
fi

python3 tools/send_widget.py --config "$CONFIG" check
python3 tools/send_widget.py --config "$CONFIG" send \
    --html "$HTML" \
    --caption 'Authorized Telegram Android Calculator widget test' \
    --height 590 \
    --confirm-own-private-chat
