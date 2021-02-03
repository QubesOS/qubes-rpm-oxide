#!/bin/sh --
set -eu

dir=$(mktemp -d)
mkfifo -- "$dir/s"
cargo run --release --bin=rpmcanon -- "$1" "$dir/s.rpm" &
sudo dnf -C reinstall -- "$dir/s.rpm"
wait
