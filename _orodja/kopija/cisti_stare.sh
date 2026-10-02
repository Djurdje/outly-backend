#!/usr/bin/env bash
# Hramba: izbrise kopije v R2, starejse od R2_HRAMBA_DNI (privzeto 30). Uporaba: cisti_stare.sh
# Varovala: brise SAMO kljuce kopije/YYYY/MM/outly-db-*.gpg|.sha256 (nikoli kopije/stanje/...); vedno ohrani najnovejsih
# R2_MIN_KOPIJ (privzeto 7) kopij ne glede na starost (ce kopije prenehajo nastajati, se zaloga ne izprazni).
# Varovalka ure: najnovejsa kopija in »zdaj« se ne smeta razlikovati za > 2 dni, sicer nic ne brisemo (opozorilo).
# R2_ZDAJ = epoch sekunde (samo za preizkus). Izpis: samo stevila.
set -euo pipefail
SKRIPTA="$(dirname "$0")/r2.sh"
HRAMBA_DNI="${R2_HRAMBA_DNI:-30}"
MIN_KOPIJ="${R2_MIN_KOPIJ:-7}"
ZDAJ="${R2_ZDAJ:-$(date -u +%s)}"
MEJA=$(( ZDAJ - HRAMBA_DNI * 86400 ))
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

bash "$SKRIPTA" list "kopije/20" > "$TMP/seznam.tsv"
# samo veljavni kljuci kopij
grep -E $'^kopije/[0-9]{4}/[0-9]{2}/outly-db-[0-9-]+-r[0-9]+(-[0-9]+)?\\.json\\.gz\\.gpg(\\.sha256)?\t' "$TMP/seznam.tsv" > "$TMP/kopije.tsv" || true
# kopije = .gpg objekti, najnovejsi prvi (po casu spremembe)
while IFS=$'\t' read -r kljuc cas _; do
  case "$kljuc" in *.gpg) printf '%s\t%s\n' "$(date -u -d "$cas" +%s)" "$kljuc" ;; esac
done < "$TMP/kopije.tsv" | sort -rn > "$TMP/gpg.tsv"
SKUPAJ=$(wc -l < "$TMP/gpg.tsv")
# Varovalka ure: ce je »zdaj« za vec kot 2 dni pred najnovejso kopijo ali vec kot 2 dni za njo (kopije ne nastajajo / ura je napacna),
# ne brisemo nicesar - sicer bi napacna ura ali zaustavljen workflow izpraznila zalogo.
if [ "$SKUPAJ" -gt 0 ]; then
  NAJNOVEJSA=$(head -n1 "$TMP/gpg.tsv" | cut -f1)
  RAZLIKA=$(( ZDAJ - NAJNOVEJSA ))
  if [ "$RAZLIKA" -gt 172800 ] || [ "$RAZLIKA" -lt -172800 ]; then
    echo "::warning::Hramba: najnovejsa kopija se od danasnjega casa razlikuje za vec kot 2 dni (kopije ne nastajajo ali ura ni prava); nicesar ne brisem."
    [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "Hramba: **preskocena** (najnovejsa kopija se razlikuje od casa za > 2 dni), nic izbrisanega." >> "$GITHUB_STEP_SUMMARY"
    exit 0
  fi
fi
head -n "$MIN_KOPIJ" "$TMP/gpg.tsv" | cut -f2 > "$TMP/zascitene.txt"

BRISANO=0
while IFS=$'\t' read -r kljuc cas _; do
  t=$(date -u -d "$cas" +%s)
  [ "$t" -lt "$MEJA" ] || continue
  osnova="${kljuc%.sha256}"
  if grep -qxF "$osnova" "$TMP/zascitene.txt"; then continue; fi
  bash "$SKRIPTA" delete "$kljuc"
  BRISANO=$((BRISANO + 1))
done < "$TMP/kopije.tsv"
echo "Hramba: kopij v R2 $SKUPAJ, izbrisanih objektov (starejsih od $HRAMBA_DNI dni): $BRISANO"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "Hramba: kopij v R2 $SKUPAJ, izbrisanih objektov starejsih od $HRAMBA_DNI dni: $BRISANO." >> "$GITHUB_STEP_SUMMARY"
