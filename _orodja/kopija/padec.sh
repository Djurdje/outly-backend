#!/usr/bin/env bash
# Izhodisce za preverbo padca stevila vrstic (users/orders/tickets). Stevila so poslovna informacija, zato je izhodisce SIFRIRANO
# (openssl aes-256-cbc, pbkdf2, kljuc BACKUP_STEVILA_KLJUC iz environmenta »kopije«) in hranjeno v ZASEBNEM R2 bucketu:
#   kopije/stanje/stevila.enc          sifrirana stevila prejsnjega zagona
#   kopije/stanje/brez-izhodisca       oznaka: izhodisca ni bilo ze ob prejsnjem zagonu (pisemo ob »stanje«, brisemo ob uspesnem »preveri«)
# Dva ukaza:
#   padec.sh stanje             ugotovi, ali je izhodisce berljivo; opozorilo + vrstica v povzetku; v $GITHUB_OUTPUT: izhodisce=1|0, dvakrat=true|false
#   padec.sh preveri <izvoz>    primerja z izhodiscem (stevila.js padec), izhodisce znova zasifrira in shrani, pobrise oznako
# Brez izhodisca (prvi zagon, izbrisan objekt, ZAMENJAN KLJUC): opozorilo, izhodisce se nastavi na novo. Ce izhodisca ni 2 zagona
# zapored (oznaka ze obstaja), je zagon rdec. Prvi zagon (v R2 se ni nobene kopije) je dovoljen. Okolje R2_* kot r2.sh.
set -euo pipefail

: "${BACKUP_STEVILA_KLJUC:?manjka BACKUP_STEVILA_KLJUC}"
UKAZ="${1:?Uporaba: padec.sh stanje | preveri <izvoz.json>}"
R2="$(dirname "$0")/r2.sh"
KLJUC_STEVILA="kopije/stanje/stevila.enc"
KLJUC_OZNAKA="kopije/stanje/brez-izhodisca"
umask 077
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

povzetek() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$1" >> "$GITHUB_STEP_SUMMARY" || true; }
izhod() { [ -n "${GITHUB_OUTPUT:-}" ] && echo "$1" >> "$GITHUB_OUTPUT" || true; }

# 0 = berljivo (v $TMP/prej.json), 1 = obstaja a se ne da dekodirati, 2 = ni objekta
preberi() {
  local rc=0
  bash "$R2" exists "$KLJUC_STEVILA" || rc=$?
  [ "$rc" -eq 1 ] && return 2
  [ "$rc" -eq 0 ] || exit 1            # prava napaka R2 (dovoljenja, povezava): zagon naj pade, ne molci
  bash "$R2" get "$KLJUC_STEVILA" "$TMP/stevila.enc"
  if openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_STEVILA_KLJUC -in "$TMP/stevila.enc" -out "$TMP/prej.json" 2>/dev/null \
     && jq -e 'type == "object"' "$TMP/prej.json" > /dev/null 2>&1; then
    return 0
  fi
  rm -f "$TMP/prej.json"
  return 1
}

case "$UKAZ" in
  stanje)
    RC=0; preberi || RC=$?
    if [ "$RC" -eq 0 ]; then
      echo "Izhodisce za preverbo padca: prisotno."
      izhod "izhodisce=1"; izhod "dvakrat=false"
      exit 0
    fi
    if [ "$RC" -eq 1 ]; then
      RAZLOG="obstaja, a se ne da dekodirati (zamenjan BACKUP_STEVILA_KLJUC ali pokvarjen objekt)"
    else
      RAZLOG="ni (prvi zagon ali objekt izbrisan)"
    fi
    echo "::warning::Izhodisce za preverbo padca $RAZLOG; preverba padca je ta dan preskocena, izhodisce se nastavi na novo."
    povzetek "- **Izhodisce za preverbo padca:** $RAZLOG. Preverba padca ta dan preskocena, izhodisce nastavljeno na novo."
    izhod "izhodisce=0"
    # Prvi zagon? Se ni nobene kopije v R2 (stanje tece PRED nalaganjem danasnje).
    BILE=$(bash "$R2" list "kopije/20" | grep -c . || true)
    if [ "$BILE" -eq 0 ]; then
      echo "V R2 se ni nobene kopije: prvi zagon, odsotnost izhodisca je pricakovana."
      izhod "dvakrat=false"
      exit 0
    fi
    ROC=0; bash "$R2" exists "$KLJUC_OZNAKA" || ROC=$?
    if [ "$ROC" -eq 0 ]; then
      echo "::error::Izhodisca ni ze 2 zagona zapored. Kljuc BACKUP_STEVILA_KLJUC se menja ali shranjevanje izhodisca ne uspe: preglej."
      povzetek "- **NAPAKA:** izhodisca ni ze 2 zagona zapored."
      izhod "dvakrat=true"
    elif [ "$ROC" -eq 1 ]; then
      printf '%s\n' "$(date -u +%FT%TZ)" > "$TMP/oznaka.txt"
      bash "$R2" put "$TMP/oznaka.txt" "$KLJUC_OZNAKA"
      izhod "dvakrat=false"
    else
      exit 1
    fi
    ;;
  preveri)
    IZVOZ="${2:?izvoz.json}"
    PREJ="$TMP/stevila.json"
    if preberi; then mv "$TMP/prej.json" "$PREJ"; else rm -f "$PREJ"; fi
    node "$(dirname "$0")/stevila.js" padec "$IZVOZ" "$PREJ"
    # stevila.js je zapisal nova stevila (pri padcu brez potrditve konca z napako, sem ne pride)
    openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_STEVILA_KLJUC -in "$PREJ" -out "$TMP/stevila.enc.novo"
    bash "$R2" put "$TMP/stevila.enc.novo" "$KLJUC_STEVILA"
    bash "$R2" delete "$KLJUC_OZNAKA"      # brez oznake je delete v S3 uspesen tudi, ce je ni
    echo "Izhodisce shranjeno (sifrirano, R2)."
    ;;
  *) echo "Neznan ukaz"; exit 2 ;;
esac
