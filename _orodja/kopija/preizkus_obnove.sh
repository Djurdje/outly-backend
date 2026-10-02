#!/usr/bin/env bash
# Dnevna kopija, korak 3: preizkus obnove. Izvoz (golo besedilo, se pred sifriranjem) obnovi v PRAZNO lokalno bazo
# (DATABASE_URL mora kazati na localhost, npr. service container postgres:16) z istim postopkom kot prava obnova
# (ARCHITECTURE.md, »Varnostne kopije in obnova«): migracije -> pobrisi seed agent@outly.si -> db/obnovi_izvoz.js ->
# neodvisna primerjava stevil vrstic po tabelah in seznama migracij.
# Uporaba: preizkus_obnove.sh <izvoz.json>     (poganjaj iz korena repozitorija)
#
# V dnevnik gredo samo imena tabel in stevila. Sporocila napak, ki bi lahko vsebovala vrednosti iz baze
# (pg napake tipa »Key (email)=(...)«), se NE izpisujejo.
set -euo pipefail

IZVOZ="${1:?Uporaba: preizkus_obnove.sh <izvoz.json>}"
: "${DATABASE_URL:?manjka DATABASE_URL (ciljna LOKALNA baza)}"
case "$DATABASE_URL" in
  *@localhost[:/]*) ;;
  *) echo "::error::DATABASE_URL ni localhost - preizkus obnove nikoli ne sme pisati v tujo bazo."; exit 1 ;;
esac
DELOVNA="$(mktemp -d)"
trap 'rm -rf "$DELOVNA"' EXIT

npm run --silent migrate > "$DELOVNA/migrate.log" 2>&1 || { echo "::error::Migracije na prazni bazi so padle (glej zagon testi.yml)."; tail -n 3 "$DELOVNA/migrate.log" | cut -c1-200; exit 1; }
echo "Migracije: OK ($(grep -c . "$DELOVNA/migrate.log") vrstic izpisa)"

node _orodja/kopija/stevila.js pocisti-seed

if ! node db/obnovi_izvoz.js "$IZVOZ" > "$DELOVNA/obnova.log" 2>&1; then
  echo "::error::Obnova izvoza je padla."
  if grep -q 'Nepričakovana napaka' "$DELOVNA/obnova.log"; then
    echo "(podrobnosti skrite: nepricakovana napaka lahko vsebuje vrednosti iz baze; ponovi lokalno po skillu obnova-baze)"
  else
    grep -A8 '✖' "$DELOVNA/obnova.log" | cut -c1-300 || true
  fi
  exit 1
fi
cat "$DELOVNA/obnova.log"

node _orodja/kopija/stevila.js primerjaj "$IZVOZ"
