#!/usr/bin/env bash
# Tanek ovoj za Cloudflare R2 (S3 API prek aws CLI, ki je na ubuntu-latest). Uporaba:
#   r2.sh put <lokalna-datoteka> <kljuc>      nalozi (multipart samo, ce je treba; aws s3 cp)
#   r2.sh get <kljuc> <lokalna-datoteka>      prenese
#   r2.sh list <predpona>                     vrstica na objekt: kljuc<TAB>cas-spremembe<TAB>velikost
#   r2.sh exists <kljuc>                      koda 0 = obstaja, 1 = ne obstaja
#   r2.sh delete <kljuc>
#
# Okolje (GitHub environment »kopije«; NIKOLI se ne izpisuje):
#   R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET
#   neobvezno: R2_ENDPOINT (preglasitev, lokalni preizkus z moto/MinIO), R2_REGION (privzeto auto)
# Endpoint za EU jurisdikcijo: https://<ACCOUNT_ID>.eu.r2.cloudflarestorage.com (brez .eu bi bil globalni, bucket v EU pa ga ne bi nasel).
#
# Dnevnik je javen: napake aws CLI (ki lahko vsebujejo URL z ID-jem racuna ali ime bucketa) se NE izpisujejo;
# izpise se samo koda napake S3 (npr. AccessDenied, NoSuchBucket) ali »povezava«.
set -euo pipefail

UKAZ="${1:?Uporaba: r2.sh put|get|list|exists|delete ...}"
: "${R2_ACCESS_KEY_ID:?manjka R2_ACCESS_KEY_ID}" "${R2_SECRET_ACCESS_KEY:?manjka R2_SECRET_ACCESS_KEY}" "${R2_BUCKET:?manjka R2_BUCKET}"
if [ -z "${R2_ENDPOINT:-}" ]; then
  : "${R2_ACCOUNT_ID:?manjka R2_ACCOUNT_ID}"
  R2_ENDPOINT="https://${R2_ACCOUNT_ID}.eu.r2.cloudflarestorage.com"
fi
export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="${R2_REGION:-auto}" AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
# Novejsi aws CLI privzeto dodaja CRC checksum glave; R2 jih zahteva samo ob potrebi (Cloudflare priporocilo za S3 odjemalce).
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required

ERR="$(mktemp)"
trap 'rm -f "$ERR"' EXIT

# Zazene aws; ob napaki izpise samo kodo in vrne njeno izhodno kodo.
aws_() {
  local rc=0
  aws --endpoint-url "$R2_ENDPOINT" "$@" 2> "$ERR" || rc=$?
  if [ "$rc" -ne 0 ]; then
    local koda
    koda=$(grep -o -m1 'An error occurred ([A-Za-z0-9]*)' "$ERR" | sed -E 's/.*\(([A-Za-z0-9]*)\).*/\1/' || true)
    echo "R2: napaka ($UKAZ): ${koda:-povezava ali neznano}" >&2
  fi
  return "$rc"
}

case "$UKAZ" in
  put)
    aws_ s3 cp --only-show-errors "${2:?datoteka}" "s3://$R2_BUCKET/${3:?kljuc}" > /dev/null
    ;;
  get)
    aws_ s3 cp --only-show-errors "s3://$R2_BUCKET/${2:?kljuc}" "${3:?datoteka}" > /dev/null
    ;;
  list)
    # aws s3api list-objects-v2 sam strani; brez zadetkov izpise »None«
    aws_ s3api list-objects-v2 --bucket "$R2_BUCKET" --prefix "${2:-}" \
      --query 'Contents[].[Key,LastModified,Size]' --output text | { grep -v '^None$' || true; }
    ;;
  exists)
    RC=0; aws --endpoint-url "$R2_ENDPOINT" s3api head-object --bucket "$R2_BUCKET" --key "${2:?kljuc}" > /dev/null 2> "$ERR" || RC=$?
    if [ "$RC" -ne 0 ]; then
      # head-object vrne 404 (Not Found); vse ostalo (dovoljenja, povezava) je prava napaka
      if grep -q -E 'Not Found|NoSuchKey|404' "$ERR"; then exit 1; fi
      KODA=$(grep -o -m1 'An error occurred ([A-Za-z0-9]*)' "$ERR" | sed -E 's/.*\(([A-Za-z0-9]*)\).*/\1/' || true)
      echo "R2: napaka (exists): ${KODA:-povezava ali neznano}" >&2
      exit 2
    fi
    ;;
  delete)
    aws_ s3api delete-object --bucket "$R2_BUCKET" --key "${2:?kljuc}" > /dev/null
    ;;
  *) echo "Neznan ukaz" >&2; exit 2 ;;
esac
