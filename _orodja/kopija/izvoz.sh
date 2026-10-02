#!/usr/bin/env bash
# Dnevna kopija, korak 1: prijava servisnega admin racuna (Supabase Auth) in prenos
# GET /admin/api/export v datoteko. Uporaba: izvoz.sh <izhodna-datoteka.json>
#
# Skrivnosti prihajajo SAMO iz okolja (GitHub secrets):
#   BACKUP_ADMIN_EMAIL, BACKUP_ADMIN_PASSWORD  racun z vlogo admin
# Preglasitve za lokalni preizkus: BACKEND_URL, SUPABASE_URL, SUPABASE_APIKEY.
#
# V dnevnik (javen!) pride samo: HTTP status, velikost, imena tabel in stevila vrstic.
# Odgovorov streznika se NE izpisuje (lahko bi vsebovali e-naslove ali kaj drugega).
set -euo pipefail

IZHOD="${1:?Uporaba: izvoz.sh <izhodna-datoteka.json>}"
: "${BACKUP_ADMIN_EMAIL:?manjka BACKUP_ADMIN_EMAIL}"
: "${BACKUP_ADMIN_PASSWORD:?manjka BACKUP_ADMIN_PASSWORD}"
BACKEND_URL="${BACKEND_URL:-https://outly-backend-roy3.onrender.com}"
SUPABASE_URL="${SUPABASE_URL:-https://zbewqcxnvrwebxonvebx.supabase.co}"
# Javni (publishable) kljuc, isti kot v nadzor.yml, aplikaciji in spletni strani.
SUPABASE_APIKEY="${SUPABASE_APIKEY:-sb_publishable_NzgXZhG7RGs0mZMjGYtyig_XfOvepXS}"

DELOVNA="$(mktemp -d)"
trap 'rm -rf "$DELOVNA"' EXIT
umask 077

echo "::add-mask::$BACKUP_ADMIN_PASSWORD"

# --- 1. prijava ---
jq -n --arg e "$BACKUP_ADMIN_EMAIL" --arg p "$BACKUP_ADMIN_PASSWORD" '{email:$e,password:$p}' > "$DELOVNA/prijava.json"
STATUS=$(curl -sS --max-time 30 --retry 3 --retry-delay 5 -o "$DELOVNA/odgovor.json" -w '%{http_code}' \
  -X POST "$SUPABASE_URL/auth/v1/token?grant_type=password" \
  -H "apikey: $SUPABASE_APIKEY" -H 'Content-Type: application/json' \
  --data @"$DELOVNA/prijava.json" 2>/dev/null) || STATUS=000
if [ "$STATUS" != "200" ]; then
  echo "::error::Prijava servisnega racuna ni uspela (HTTP $STATUS). Preveri BACKUP_ADMIN_EMAIL / BACKUP_ADMIN_PASSWORD (glej skill obnova-baze)."
  exit 1
fi
TOKEN=$(jq -r '.access_token // empty' "$DELOVNA/odgovor.json")
if [ -z "$TOKEN" ]; then
  echo "::error::Prijava je vrnila 200, a brez access_token."
  exit 1
fi
echo "::add-mask::$TOKEN"
rm -f "$DELOVNA/prijava.json" "$DELOVNA/odgovor.json"
echo "Prijava: OK"

# --- 2. izvoz (tok; streznik ga piše sproti). Do 3 poskusi po najvec 600 s (+ 2 x 30 s pavze = 31 min, workflow ima 50 min);
#     4xx (zeton, vloga, e-naslov ni potrjen) se ne ponavlja ---
for POSKUS in 1 2 3; do
  RC=0
  STATUS=$(curl -sS --max-time 600 -f -o "$IZHOD" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" "$BACKEND_URL/admin/api/export" 2>/dev/null) || RC=$?
  [ "$RC" -eq 0 ] && break
  rm -f "$IZHOD"
  echo "Izvoz, poskus $POSKUS/3: curl koda $RC, HTTP ${STATUS:-000}"
  case "${STATUS:-000}" in 400|401|403|404) break ;; esac   # deterministicna napaka: ponavljanje ne pomaga
  if [ "$POSKUS" -lt 3 ]; then sleep "${IZVOZ_PAVZA_S:-30}"; fi
done
if [ "$RC" -ne 0 ]; then
  echo "::error::Izvoz ni uspel (curl koda $RC, HTTP ${STATUS:-000}). 401 = zeton, 403 = racun ni admin ALI e-naslov v Supabase ni potrjen (email_verified), 5xx/pretrganje = streznik."
  exit 1
fi
echo "Izvoz: HTTP $STATUS"

# --- 3. preverba vsebine (nepopolna ali prazna kopija NI kopija) ---
if ! jq -e '
      (.exported_at | type == "string")
  and (.tables | type == "object" and length > 0)
  and (.sequences | type == "array")
  and ([.tables[] | (.rows | length) == .count] | all)
  and (.tables.schema_migrations.count > 0)
  and (.tables.users.count > 0)
' "$IZHOD" > /dev/null 2>&1; then
  echo "::error::Izvoz ni veljaven: ni JSON, je okrnjen ali se stevila vrstic ne ujemajo z .count."
  rm -f "$IZHOD"
  exit 1
fi
echo "Vsebina: veljaven JSON, $(jq '.tables | length' "$IZHOD") tabel, $(jq '.tables.schema_migrations.count' "$IZHOD") migracij"
