#!/bin/sh
set -eu

nsjail_bin=${1:-./nsjail}
fixture=$(mktemp -d)
trap 'rm -f "$fixture/text.cfg" "$fixture/config.json"; rmdir "$fixture"' EXIT

printf '%s\n' 'envar: "NSJAIL_TEST=nsjail-fixture-value"' > "$fixture/text.cfg"
printf '%s\n' '{"envar": ["NSJAIL_TEST=nsjail-fixture-value"]}' > "$fixture/config.json"

check_config_log() {
    config_file=$1
    config_format=$2
    output=$("$nsjail_bin" --verbose --config "$config_file" --help 2>&1 >/dev/null)
    printf '%s\n' "$output" | grep -F "Parsed $config_format config from" >/dev/null
    if printf '%s\n' "$output" | grep -Fq 'nsjail-fixture-value'; then
        printf '%s\n' "$config_format configuration value appeared in the debug log" >&2
        return 1
    fi
}

check_config_log "$fixture/text.cfg" TextProto
check_config_log "$fixture/config.json" JSON
