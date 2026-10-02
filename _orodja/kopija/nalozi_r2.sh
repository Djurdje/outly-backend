#!/usr/bin/env bash
# Dnevna kopija, korak: nalozi SIFRIRANO kopijo v R2 in preveri, da je tam cela. Uporaba:
#   nalozi_r2.sh <mapa-z-.age-in-.sha256> <YYYY-MM-DD> <oznaka>
# Kljuc: kopije/YYYY/MM/outly-db-YYYY-MM-DD-r<oznaka>.json.gz.age (+ .sha256); oznaka = <run_id>-<run_attempt>, zato dva zagona
# istega dne (cron + rocni) ne dasta istega kljuca. Datoteki v mapi se morata ze tako imenovati, da sha256sum -c deluje tudi po prenosu.
# Obstojece kopije NIKOLI ne prepise: ce kljuc (ali njegov .sha256) ze obstaja, zagon pade.
# Po nalaganju datoteko PRENESE NAZAJ in primerja sha256 (kopija, ki je nismo prebrali nazaj, ni dokazana kopija).
set -euo pipefail
MAPA="${1:?mapa}"; DATUM="${2:?datum}"; OZNAKA="${3:?oznaka}"
SKRIPTA="$(dirname "$0")/r2.sh"
IME="outly-db-$DATUM-r$OZNAKA.json.gz.age"
KLJUC="kopije/${DATUM:0:4}/${DATUM:5:2}/$IME"
[ -f "$MAPA/$IME" ] && [ -f "$MAPA/$IME.sha256" ] || { echo "::error::V mapi manjka $IME ali njen .sha256."; exit 1; }
umask 077
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

for k in "$KLJUC" "$KLJUC.sha256"; do
  RC=0; bash "$SKRIPTA" exists "$k" || RC=$?
  case "$RC" in
    0) echo "::error::Objekt $k ze obstaja v R2; obstojece kopije ne prepisujem."; exit 1 ;;
    1) ;;
    *) exit 1 ;;   # prava napaka R2 (r2.sh je izpisal kodo)
  esac
done
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
