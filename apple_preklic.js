// Preklic Applovih zetonov ob izbrisu racuna (Issue #427, Apple 5.1.1(v); ARCHITECTURE »Prijava z Googlom in Applom« tocka 8, I74).
//
// Apple (dokumentacija prebrana 15. 11. 2026, pogodba v komentarju Issueja #427): aplikacija s Sign in with Apple mora ob izbrisu racuna
// prek REST API preklicati uporabnikove zetone. iOS ob ponovni prijavi pred izbrisom poslje `apple_authorization_code` (enkratna, 5 min);
// backend PO uspesnem izbrisu (po COMMIT) in ne da bi odgovor cakal:
//   1. POST {APPLE_AUTH_URL}/auth/token  (client_id, client_secret, code, grant_type=authorization_code; BREZ redirect_uri: nativni iOS ga nima)
//   2. POST {APPLE_AUTH_URL}/auth/revoke (client_id, client_secret, token=refresh_token, token_type_hint=refresh_token;
//      ce refresh_token ni, access_token s token_type_hint=access_token)
// Casovna meja vsakega klica 8 s. /auth/token se NE ponovi (koda je enkratna), /auth/revoke najvec enkrat ob omrezni napaki ali 5xx.
// client_secret = JWT ES256 (vgrajen crypto, ieee-p1363), veljaven 300 s (Apple dovoli do 6 mesecev; kratko = manj vreden ob uhajanju).
//
// Neuspeh nikoli ne vpliva na izbris. V dnevnik gre samo korak, HTTP status in Applova koda napake z dovoljenega seznama (sicer »drugo»);
// NIKOLI koda, zetoni, client_secret, kljuc, e-naslov, uid ali Applov `sub`. Obljuba nikoli ne zavrne (neujeta zavrnitev ustavi proces, sentry.js).

"use strict";

const crypto = require("crypto");

const ROK_MS = 8000;
const CLIENT_SECRET_S = 300;
const DOVOLJENE_NAPAKE = new Set(["invalid_request", "invalid_client", "invalid_grant", "invalid_scope", "unsupported_grant_type"]);
const OBLIKA_KODE = /^[A-Za-z0-9._-]{1,1024}$/;

// Koda iz telesa zahtevka: samo niz dolzine 1-1024 iz [A-Za-z0-9._-]; vse drugo = null (prezrto, izbris tece naprej).
function veljavnaKoda(x) {
  return typeof x === "string" && OBLIKA_KODE.test(x) ? x : null;
}

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

// Nastavitev iz okolja. Vrne { vklopljen, razlog } in ob izklopu napise ENO opozorilo (brez vrednosti).
function nastavi(env = process.env, opozori = console.warn) {
  const manjka = ["APPLE_TEAM_ID", "APPLE_SIWA_KEY_ID", "APPLE_SIWA_KEY_P8"].filter((k) => !env[k]);
  if (manjka.length) {
    opozori(`[apple] preklic zetonov izklopljen: manjka ${manjka.join(", ")}; izbris racuna dela kot prej, Applovi zetoni ostanejo veljavni`);
    return { vklopljen: false, razlog: "manjka" };
  }
  let kljuc;
  try {
    kljuc = crypto.createPrivateKey(Buffer.from(env.APPLE_SIWA_KEY_P8, "base64").toString("utf8"));
    const d = kljuc.asymmetricKeyDetails || {};
    if (kljuc.asymmetricKeyType !== "ec" || d.namedCurve !== "prime256v1") throw new Error("ni EC P-256");
  } catch (_) {
    opozori("[apple] preklic zetonov izklopljen: kljuc ni veljaven (APPLE_SIWA_KEY_P8 mora biti base64 cele datoteke .p8, EC P-256)");
    return { vklopljen: false, razlog: "kljuc" };
  }
  return {
    vklopljen: true,
    teamId: env.APPLE_TEAM_ID,
    keyId: env.APPLE_SIWA_KEY_ID,
    clientId: env.APPLE_SIWA_CLIENT_ID || "si.outly.app",
    url: (env.APPLE_AUTH_URL || "https://appleid.apple.com").replace(/\/+$/, ""),
    kljuc,
  };
}

function clientSecret(n, zdaj = Math.floor(Date.now() / 1000)) {
  const vhod = b64u({ alg: "ES256", kid: n.keyId }) + "." +
    b64u({ iss: n.teamId, iat: zdaj, exp: zdaj + CLIENT_SECRET_S, aud: "https://appleid.apple.com", sub: n.clientId });
  const podpis = crypto.sign("sha256", Buffer.from(vhod), { key: n.kljuc, dsaEncoding: "ieee-p1363" });
  return vhod + "." + podpis.toString("base64url");
}

// En klic na Apple. Vrne { ok, status, napaka, telo } - nikoli ne vrze.
async function klic(n, pot, polja) {
  let r;
  try {
    r = await fetch(n.url + pot, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams(polja).toString(),
      signal: AbortSignal.timeout(ROK_MS),
    });
  } catch (e) {
    const casovna = e && (e.name === "TimeoutError" || e.name === "AbortError");
    return { ok: false, status: casovna ? "casovna_meja" : "omrezje", napaka: "-" };
  }
  let telo = null;
  try { const t = await r.text(); telo = t ? JSON.parse(t) : null; } catch (_) { telo = null; }
  if (r.ok) return { ok: true, status: r.status, telo };
  const koda = telo && typeof telo.error === "string" && DOVOLJENE_NAPAKE.has(telo.error) ? telo.error : "drugo";
  return { ok: false, status: r.status, napaka: koda };
}

const zapisiNeuspeh = (korak, izid, porociOpozorilo) => {
  const vrstica = `[apple] preklic ni uspel: korak=${korak} status=${izid.status} napaka=${izid.napaka}`;
  console.warn(vrstica);
  try { porociOpozorilo && porociOpozorilo(vrstica, "apple-preklic"); } catch (_) { /* nikoli */ }
};

// Izmenjava kode in preklic. Vrne obljubo, ki se VEDNO razresi (true = preklicano, false = ne).
async function preklici(n, koda, porociOpozorilo) {
  try {
    if (!n || !n.vklopljen || !koda) return false;
    const secret = clientSecret(n);
    const t = await klic(n, "/auth/token", { client_id: n.clientId, client_secret: secret, code: koda, grant_type: "authorization_code" });
    if (!t.ok) { zapisiNeuspeh("token", t, porociOpozorilo); return false; }
    const telo = t.telo || {};
    const zeton = typeof telo.refresh_token === "string" && telo.refresh_token ? { token: telo.refresh_token, hint: "refresh_token" }
      : typeof telo.access_token === "string" && telo.access_token ? { token: telo.access_token, hint: "access_token" } : null;
    if (!zeton) { zapisiNeuspeh("token", { status: t.status, napaka: "brez_zetona" }, porociOpozorilo); return false; }
    const polja = { client_id: n.clientId, client_secret: secret, token: zeton.token, token_type_hint: zeton.hint };
    let rv = await klic(n, "/auth/revoke", polja);
    const ponovi = !rv.ok && (typeof rv.status !== "number" || rv.status >= 500);
    if (ponovi) rv = await klic(n, "/auth/revoke", polja);
    if (!rv.ok) { zapisiNeuspeh("revoke", rv, porociOpozorilo); return false; }
    console.log(`[apple] zetoni preklicani (${zeton.hint})`);
    return true;
  } catch (_) {
    try { console.warn("[apple] preklic ni uspel: korak=notranje status=- napaka=-"); } catch (__) { /* nikoli */ }
    return false;
  }
}

module.exports = { nastavi, veljavnaKoda, preklici, clientSecret, ROK_MS };
