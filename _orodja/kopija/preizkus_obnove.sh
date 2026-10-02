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
  # Seznam dovoljenih (kontrolirane Zavrnitev v obnovi_izvoz.js: imena tabel/stolpcev/migracij). Vse ostalo
  # (Nepricakovana napaka, JSON.parse »ni mogoce prebrati ali razclenit« - oboje lahko vsebuje kose podatkov) se skrije.
  if grep -E '^✖ (Cilj ni prazen|Cilj nima|Seznam migracij|Število vrstic|Tabela |Stolpec |Zaporedje |Med tabelami|Izvoz ne vsebuje|Datoteka ni videti)' "$DELOVNA/obnova.log" > /dev/null; then
    # števila vrstic niso za javni dnevnik: pricakovano/dejansko in »ima N vrstic« -> N
    grep -A8 '^✖' "$DELOVNA/obnova.log" | sed -E 's/pričakovano [0-9]+, dejansko [0-9]+/stevili se ne ujemata/; s/že ima [0-9]+ vrstic/ze ima vrstice/' | cut -c1-300 || true
  else
    echo "(podrobnosti skrite: napaka lahko vsebuje vrednosti iz baze; ponovi lokalno po skillu obnova-baze)"
  fi
  exit 1
fi
# V javnem dnevniku brez stevila vrstic (poslovna informacija): samo ime tabele in OK.
echo "Obnova izvoza: OK"
grep -E '^  [a-z_0-9]+: [0-9]+ vrstic$' "$DELOVNA/obnova.log" | sed -E 's/: [0-9]+ vrstic$/: OK/'

node _orodja/kopija/stevila.js primerjaj "$IZVOZ"
