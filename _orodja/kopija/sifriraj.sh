#!/usr/bin/env bash
# Dnevna kopija, korak 2: stisni (gzip) in sifriraj z JAVNIM kljucem (age). Uporaba:
#   sifriraj.sh <izvoz.json> <izhod.json.gz.age>
# Prejemniki: BACKUP_AGE_PUBLIC_KEYS = en ali vec javnih kljucev "age1...", locenih s presledkom ali novo vrstico.
# Zasebni kljuc je samo pri Martinu — ta workflow ga nikoli ne vidi. Ob izpisu: velikost in odtis, nic drugega.
set -euo pipefail

VHOD="${1:?Uporaba: sifriraj.sh <izvoz.json> <izhod.json.gz.age>}"
IZHOD="${2:?Uporaba: sifriraj.sh <izvoz.json> <izhod.json.gz.age>}"
: "${BACKUP_AGE_PUBLIC_KEYS:?manjka BACKUP_AGE_PUBLIC_KEYS}"
umask 077

PREJEMNIKI=()
for k in $BACKUP_AGE_PUBLIC_KEYS; do
  if ! [[ "$k" =~ ^age1[0-9a-z]{58}$ ]]; then
    echo "::error::BACKUP_AGE_PUBLIC_KEYS vsebuje nekaj, kar ni javni kljuc age (age1 + 58 znakov). Zasebni kljuc (AGE-SECRET-KEY-...) NIKOLI ne sme v GitHub."
    exit 1
  fi
  PREJEMNIKI+=(-r "$k")
done
[ "${#PREJEMNIKI[@]}" -gt 0 ] || { echo "::error::Ni nobenega javnega kljuca."; exit 1; }

gzip -9 -n < "$VHOD" | age "${PREJEMNIKI[@]}" -o "$IZHOD"

# Preverba: izhod je age datoteka in v njej ni golega besedila izvoza.
head -c 40 "$IZHOD" | grep -q 'age-encryption.org/v1' || { echo "::error::Izhod ni age datoteka."; rm -f "$IZHOD"; exit 1; }
if grep -q -a '"exported_at"' "$IZHOD"; then echo "::error::V sifrirani datoteki je golo besedilo!"; rm -f "$IZHOD"; exit 1; fi

( cd "$(dirname "$IZHOD")" && sha256sum "$(basename "$IZHOD")" > "$(basename "$IZHOD").sha256" )
echo "Sifrirano: $(stat -c %s "$IZHOD") B (vhod $(stat -c %s "$VHOD") B), prejemnikov: $(( ${#PREJEMNIKI[@]} / 2 )), sha256 $(cut -c1-16 "$IZHOD.sha256")"
