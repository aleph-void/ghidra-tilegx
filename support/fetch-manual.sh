#!/usr/bin/env bash
# Download the Tilera TILE-Gx documents the generators read, by pinned URL and SHA-256:
#   support/fetch-manual.sh <dir>
#   UG401-ISA.pdf  TILE-Gx Instruction Set Architecture (instruction encodings, semantics)
#   spr.html       MDE 4.3.4 special-purpose register reference (SPR numbers and names)
#   UG513-ABI.pdf  Tile Processor Application Binary Interface (calling convention, DWARF numbers)
# Source: the MDE 4.3.4 documentation set mirrored at github.com/re-tile/docs. The documents are
# not redistributed with this module; only facts read from them (encodings, register numbers) are.
set -euo pipefail
D=${1:?usage: fetch-manual.sh <dir>}
mkdir -p "$D"
BASE=https://raw.githubusercontent.com/re-tile/docs/acefef3358d875cc66725c377fd831334776410a
while read -r sum path; do
	f=$D/$(basename "$path")
	if [[ ! -f $f ]] || ! echo "$sum  $f" | sha256sum -c --status; then
		curl -fsSL -o "$f" "$BASE/$path"
	fi
	echo "$sum  $f" | sha256sum -c --quiet
done <<'LIST'
bce9a82b10f59b7cc0675dcd64b1abc6bf9afacd0eccdd8905c112826ffb69de pdf/UG401-ISA.pdf
a2f3a70983b03565a545ba2cdabb7152db8394372709520cfd111e223783aed4 html/spr.html
2379bf05a761a480e73ece1c9c479d1ed1cfa203f05f498250410de661a9c055 pdf/UG513-ABI.pdf
LIST
