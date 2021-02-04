#!/bin/sh --
set -eu

if [ "$#" -ne 1 ]; then echo 'Usage: mkfifo.sh PACKAGE'>&2; exit 1; fi
dir=$(mktemp -d)
mkfifo -- "$dir/s"
cargo run --release --bin=rpmcanon -- "$1" "$dir/s.rpm" &
sudo dnf -C reinstall -- "$dir/s.rpm"
wait
