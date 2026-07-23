#!/usr/bin/env sh
set -eu

mode="${1:-fix}"

case "$mode" in
  fix | --fix)
    clang_format_args="-i"
    ;;
  check | --check)
    clang_format_args="--dry-run --Werror"
    ;;
  *)
    echo "Usage: $0 [fix|check]" >&2
    exit 2
    ;;
esac

files=$(
  find include src test/stubs -type f \( -name '*.c' -o -name '*.h' \)
  find test -maxdepth 1 -type f -name '*.c'
)

if [ -z "$files" ]; then
  exit 0
fi

# shellcheck disable=SC2086
clang-format $clang_format_args $files
