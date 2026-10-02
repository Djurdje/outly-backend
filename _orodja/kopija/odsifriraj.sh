#!/usr/bin/env bash
# Odsifrira in razpakira kopijo. Uporaba:  odsifriraj.sh <kopija.json.gz.gpg> <izvoz.json>
# Geslo: okolje BACKUP_GESLO (v GitHub Actions iz secreta; geslo NE zapusti GitHuba). Martin lokalno uporabi gpg z vpisom gesla (SKILL obnova-baze).
# Zavrne spremenjeno datoteko (MDC) in napacno geslo; v izpis ne pride nic iz vsebine.
set -euo pipefail
VHOD="${1:?Uporaba: odsifriraj.sh <kopija.json.gz.gpg> <izvoz.json>}"
IZHOD="${2:?Uporaba: odsifriraj.sh <kopija.json.gz.gpg> <izvoz.json>}"
umask 077
# shellcheck source=_orodja/kopija/gpg_skupno.sh
. "$(dirname "$0")/gpg_skupno.sh"
gpg_pripravi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; gpg_pocisti' EXIT

if ! gpg_odsifriraj "$VHOD" "$TMP/izvoz.json.gz"; then
  echo "::error::Odsifriranje ni uspelo (napacno BACKUP_GESLO ali spremenjena/pokvarjena datoteka)."
  exit 1
fi
if ! gzip -dc "$TMP/izvoz.json.gz" > "$IZHOD" 2> /dev/null; then
  rm -f "$IZHOD"; echo "::error::Razpakiranje (gzip) ni uspelo."; exit 1
fi
echo "Odsifriranje in razpakiranje: OK"
