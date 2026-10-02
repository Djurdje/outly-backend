#!/usr/bin/env bash
# Dnevna kopija, korak 2: stisni (gzip) in sifriraj z GESLOM (gpg, AES-256, simetricno). Uporaba:
#   sifriraj.sh <izvoz.json> <izhod.json.gz.gpg>
# Geslo: okolje BACKUP_GESLO (GitHub environment secret »kopije«, >= 32 znakov, brez nove vrstice). Nikoli v ukazni vrstici ali izpisu.
# Integriteta: gpg doda MDC (modification detection code, SHA-1 nad celim paketom) - spremenjena datoteka se pri desifriranju zavrne;
# poleg tega ima vsaka kopija v R2 svoj .sha256 (nalozi_r2.sh ga primerja po prenosu). Ob izpisu: velikost (zaokrozena na MB) in odtis.
# Sprejeto tveganje (DECISIONS 2. 10. 2026): kdor lahko bere secrets environmenta »kopije«, lahko odsifrira kopije.
set -euo pipefail

VHOD="${1:?Uporaba: sifriraj.sh <izvoz.json> <izhod.json.gz.gpg>}"
IZHOD="${2:?Uporaba: sifriraj.sh <izvoz.json> <izhod.json.gz.gpg>}"
umask 077
# shellcheck source=_orodja/kopija/gpg_skupno.sh
. "$(dirname "$0")/gpg_skupno.sh"
gpg_pripravi
trap gpg_pocisti EXIT

rm -f "$IZHOD"
gzip -9 -n < "$VHOD" | gpg_sifriraj "$IZHOD"

# Preverba: izhod je gpg simetricni paket z MDC in v njem ni golega besedila izvoza.
PAKETI="$(gpg --batch --list-packets "$IZHOD" 2> /dev/null || true)"
if ! grep -q 'symkey enc packet' <<< "$PAKETI" || ! grep -q 'mdc_method: 2' <<< "$PAKETI" || ! grep -q 'cipher 9' <<< "$PAKETI"; then
  echo "::error::Izhod ni gpg simetricni paket AES-256 z MDC."; rm -f "$IZHOD"; exit 1
fi
if grep -q -a '"exported_at"' "$IZHOD"; then echo "::error::V sifrirani datoteki je golo besedilo!"; rm -f "$IZHOD"; exit 1; fi

( cd "$(dirname "$IZHOD")" && sha256sum "$(basename "$IZHOD")" > "$(basename "$IZHOD").sha256" )
echo "Sifrirano: ~$(( ( $(stat -c %s "$IZHOD") + 1048575 ) / 1048576 )) MB, sha256 $(cut -c1-16 "$IZHOD.sha256")"
