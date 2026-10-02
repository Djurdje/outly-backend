#!/usr/bin/env bash
# Dnevna kopija, korak: nalozi SIFRIRANO kopijo v R2 in preveri, da je tam cela. Uporaba:
#   nalozi_r2.sh <mapa-z-.age-in-.sha256> <YYYY-MM-DD> <poskus>
# Kljuc: kopije/YYYY/MM/outly-db-YYYY-MM-DD-r<poskus>.json.gz.age (+ .sha256). Datoteki v mapi se morata ze tako imenovati
# (sifriraj.sh dobi ime z -r<poskus>), da sha256sum -c deluje tudi po prenosu.
# Po nalaganju datoteko PRENESE NAZAJ in primerja sha256 (kopija, ki je nismo prebrali nazaj, ni dokazana kopija).
set -euo pipefail
MAPA="${1:?mapa}"; DATUM="${2:?datum}"; POSKUS="${3:?poskus}"
SKRIPTA="$(dirname "$0")/r2.sh"
IME="outly-db-$DATUM-r$POSKUS.json.gz.age"
KLJUC="kopije/${DATUM:0:4}/${DATUM:5:2}/$IME"
[ -f "$MAPA/$IME" ] && [ -f "$MAPA/$IME.sha256" ] || { echo "::error::V mapi manjka $IME ali njen .sha256."; exit 1; }
umask 077
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

bash "$SKRIPTA" put "$MAPA/$IME" "$KLJUC"
bash "$SKRIPTA" put "$MAPA/$IME.sha256" "$KLJUC.sha256"
bash "$SKRIPTA" get "$KLJUC" "$TMP/$IME"
LOKALNO=$(sha256sum "$MAPA/$IME" | cut -d' ' -f1)
NAZAJ=$(sha256sum "$TMP/$IME" | cut -d' ' -f1)
if [ "$LOKALNO" != "$NAZAJ" ]; then
  echo "::error::Kopija v R2 se po prenosu nazaj ne ujema z lokalno (sha256)."
  exit 1
fi
echo "R2: kopija $KLJUC nalozena in preverjena nazaj (sha256 ${NAZAJ:0:16})"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "R2: kopija \`$KLJUC\` naloženo in preverjeno nazaj (sha256 \`${NAZAJ:0:16}\`)." >> "$GITHUB_STEP_SUMMARY"
