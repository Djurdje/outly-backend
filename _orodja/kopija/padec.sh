#!/usr/bin/env bash
# Izhodisce za preverbo padca stevila vrstic (users/orders/tickets). Stevila so poslovna informacija, actions/cache v javnem repu pa je
# berljiv workflowom iz PR-jev, zato so v cachu SIFRIRANA (openssl aes-256-cbc, pbkdf2) s kljucem BACKUP_STEVILA_KLJUC iz environmenta »kopije«.
# Dva ukaza:
#   padec.sh stanje <mapa-cache>             ugotovi, ali je izhodisce berljivo; izpise opozorilo in vrstico v povzetek;
#                                            v $GITHUB_OUTPUT: izhodisce=1|0, dvakrat=true|false (izhodisca ni ze 2 zagona zapored)
#   padec.sh preveri <izvoz.json> <mapa-cache>   primerja z izhodiscem (stevila.js padec) in izhodisce znova zasifrira
# Brez izhodisca (prvi zagon, cache pretekel/izgubljen, ZAMENJAN KLJUC): opozorilo, izhodisce se nastavi na novo.
# »Dvakrat zapored« = izhodisca ni zdaj IN je artefakt prejsnjega zagona (ime ...-b0) ze nastal brez njega. Prvi zagon (ni nobene prejsnje
# kopije) je dovoljen. Stanje nosi ime artefakta (-b0/-b1), ker cache sam ne more povedati, da je bil izgubljen.
set -euo pipefail

: "${BACKUP_STEVILA_KLJUC:?manjka BACKUP_STEVILA_KLJUC}"
UKAZ="${1:?Uporaba: padec.sh stanje <mapa> | preveri <izvoz.json> <mapa>}"
umask 077
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

povzetek() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$1" >> "$GITHUB_STEP_SUMMARY" || true; }
izhod() { [ -n "${GITHUB_OUTPUT:-}" ] && echo "$1" >> "$GITHUB_OUTPUT" || true; }

# Poskusi prebrati izhodisce v $TMP/prej.json; vrne 0 samo ce je dekodirano in je veljaven JSON objekt.
preberi() {
  local enc="$1/stevila.enc"
  [ -f "$enc" ] || return 2
  if openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_STEVILA_KLJUC -in "$enc" -out "$TMP/prej.json" 2>/dev/null \
     && jq -e 'type == "object"' "$TMP/prej.json" > /dev/null 2>&1; then
    return 0
  fi
  rm -f "$TMP/prej.json"
  return 1
}

case "$UKAZ" in
  stanje)
    MAPA="${2:?mapa}"
    RC=0; preberi "$MAPA" || RC=$?
    if [ "$RC" -eq 0 ]; then
      echo "Izhodisce za preverbo padca: prisotno."
      izhod "izhodisce=1"; izhod "dvakrat=false"
      exit 0
    fi
    if [ "$RC" -eq 1 ]; then
      RAZLOG="obstaja, a se ne da dekodirati (zamenjan BACKUP_STEVILA_KLJUC ali pokvarjen cache)"
    else
      RAZLOG="ni (prvi zagon, cache pretekel ali izgubljen)"
    fi
    echo "::warning::Izhodisce za preverbo padca $RAZLOG; preverba padca je ta dan preskocena, izhodisce se nastavi na novo."
    povzetek "- **Izhodisce za preverbo padca:** $RAZLOG. Preverba padca ta dan preskocena, izhodisce nastavljeno na novo."
    izhod "izhodisce=0"
    # Je to prvi zagon? Pogledamo, ali obstaja kaksna prejsnja kopija in kaj pove njeno ime (-b0 = tudi takrat izhodisca ni bilo).
    PREJ_IME=""
    if [ -n "${GH_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
      PREJ_IME=$(gh api --paginate "repos/$GITHUB_REPOSITORY/actions/artifacts?per_page=100" --jq '.artifacts[]' \
        | jq -rs '[ .[] | select(.name | startswith("outly-db-kopija-")) | select(.expired == false) ] | sort_by(.created_at) | reverse | (.[0].name // "")') || PREJ_IME="?"
    fi
    if [ "$PREJ_IME" = "?" ]; then
      echo "::warning::Seznama prejsnjih artefaktov ni bilo mogoce prebrati; dvojna odsotnost izhodisca ni preverjena."
      izhod "dvakrat=false"
    elif [ -z "$PREJ_IME" ]; then
      echo "Prejsnjih kopij ni: prvi zagon, odsotnost izhodisca je pricakovana."
      izhod "dvakrat=false"
    elif [[ "$PREJ_IME" == *-b0 ]]; then
      echo "::error::Izhodisca ni ze 2 zagona zapored (prejsnja kopija je nastala brez njega). Cache se ne ohranja ali BACKUP_STEVILA_KLJUC se menja: preglej."
      povzetek "- **NAPAKA:** izhodisca ni ze 2 zagona zapored."
      izhod "dvakrat=true"
    else
      izhod "dvakrat=false"
    fi
    ;;
  preveri)
    IZVOZ="${2:?izvoz.json}"; MAPA="${3:?mapa}"
    mkdir -p "$MAPA"
    PREJ="$TMP/stevila.json"
    if preberi "$MAPA"; then mv "$TMP/prej.json" "$PREJ"; else rm -f "$PREJ"; fi
    node "$(dirname "$0")/stevila.js" padec "$IZVOZ" "$PREJ"
    # stevila.js je zapisal nova stevila (pri padcu brez potrditve konca z napako, sem ne pride)
    openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_STEVILA_KLJUC -in "$PREJ" -out "$MAPA/stevila.enc"
    echo "Izhodisce shranjeno (sifrirano)."
    ;;
  *) echo "Neznan ukaz"; exit 2 ;;
esac
