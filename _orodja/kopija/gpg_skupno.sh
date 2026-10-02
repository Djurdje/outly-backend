#!/usr/bin/env bash
# Skupne funkcije za simetricno sifriranje kopije z gpg (vkljuci s `source`). Geslo je v okolju BACKUP_GESLO (GitHub environment secret
# »kopije«) in NIKOLI ni v ukazni vrstici ali izpisu: gpg ga dobi prek deskriptorja 3 (printf je vgrajen ukaz bash, ne vidi se v `ps`).
# Zacasen GNUPGHOME na runnerju/racunalniku, da gpg-agent in predpomnilnik gesel ne ostaneta.

gpg_pripravi() {
  : "${BACKUP_GESLO:?manjka BACKUP_GESLO}"
  if [ "${#BACKUP_GESLO}" -lt 32 ]; then
    echo "::error::BACKUP_GESLO je prekratko (najmanj 32 znakov)."; return 1
  fi
  case "$BACKUP_GESLO" in
    *$'\n'*|*$'\r'*) echo "::error::BACKUP_GESLO ne sme vsebovati novih vrstic (gpg bere samo prvo)."; return 1 ;;
  esac
  GNUPGHOME="$(mktemp -d)"; chmod 700 "$GNUPGHOME"; export GNUPGHOME
}

gpg_pocisti() {
  [ -n "${GNUPGHOME:-}" ] && [ -d "$GNUPGHOME" ] || return 0
  gpgconf --kill gpg-agent > /dev/null 2>&1 || true
  rm -rf "$GNUPGHOME"
}

# gpg_sifriraj <izhod>      vhod na stdin
gpg_sifriraj() {
  gpg --batch --yes --quiet --no-tty --pinentry-mode loopback --no-symkey-cache --passphrase-fd 3 \
      --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712 \
      --compress-algo none -o "$1" 3< <(printf '%s' "$BACKUP_GESLO")
}

# gpg_odsifriraj <vhod> <izhod>
gpg_odsifriraj() {
  gpg --batch --yes --quiet --no-tty --pinentry-mode loopback --no-symkey-cache --passphrase-fd 3 \
      --decrypt -o "$2" "$1" 3< <(printf '%s' "$BACKUP_GESLO") 2> /dev/null
}
