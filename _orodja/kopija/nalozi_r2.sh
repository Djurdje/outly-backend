#!/usr/bin/env bash
# Dnevna kopija, korak: nalozi SIFRIRANO kopijo v R2 in preveri, da je tam cela. Uporaba:
#   nalozi_r2.sh <mapa-z-.gpg-in-.sha256> <YYYY-MM-DD> <oznaka> [<izvoz.json>]
# Kljuc: kopije/YYYY/MM/outly-db-YYYY-MM-DD-r<oznaka>.json.gz.gpg (+ .sha256); oznaka = <run_id>-<run_attempt>, zato dva zagona
# istega dne (cron + rocni) ne dasta istega kljuca. Datoteki v mapi se morata ze tako imenovati, da sha256sum -c deluje tudi po prenosu.
# Obstojece kopije NIKOLI ne prepise: ce kljuc (ali njegov .sha256) ze obstaja, zagon pade.
# Po nalaganju datoteko PRENESE NAZAJ in primerja sha256 (kopija, ki je nismo prebrali nazaj, ni dokazana kopija).
# Ce je podan <izvoz.json> (golo besedilo, ki je bilo sifrirano): prenesena kopija se z BACKUP_GESLO ODSIFRIRA in mora biti bajt za bajtom
# enaka izvozu - vsak dan dokaz, da geslo res odpre kopijo, ki lezi v R2.
set -euo pipefail
MAPA="${1:?mapa}"; DATUM="${2:?datum}"; OZNAKA="${3:?oznaka}"; IZVOZ="${4:-}"
SKRIPTA="$(dirname "$0")/r2.sh"
IME="outly-db-$DATUM-r$OZNAKA.json.gz.gpg"
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
if [ -n "$IZVOZ" ]; then
  bash "$(dirname "$0")/odsifriraj.sh" "$TMP/$IME" "$TMP/izvoz.json"
  if ! cmp -s "$TMP/izvoz.json" "$IZVOZ"; then
    echo "::error::Odsifrirana kopija iz R2 se ne ujema z izvozom (bajt za bajtom)."
    exit 1
  fi
  echo "R2: kopija se odsifrira in je enaka izvozu"
fi
echo "R2: kopija $KLJUC nalozena in preverjena nazaj (sha256 ${NAZAJ:0:16})"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "R2: kopija \`$KLJUC\` naloženo in preverjeno nazaj (sha256 \`${NAZAJ:0:16}\`)." >> "$GITHUB_STEP_SUMMARY"
