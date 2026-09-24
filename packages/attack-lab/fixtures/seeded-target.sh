#!/bin/sh
set -eu

mode="${1:-health}"

case "$mode" in
  health)
    printf '%s\n' 'fixture-shell-ok'
    ;;
  secret)
    if [ "${FIXTURE_TOKEN:-}" = "allow" ]; then
      printf '%s\n' 'fixture-shell-secret'
      exit 0
    fi
    printf '%s\n' 'unauthorized' >&2
    exit 23
    ;;
  *)
    printf '%s\n' 'not_found' >&2
    exit 2
    ;;
esac
