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

// Applove identitete racuna iz ne-zapisljivega vira: GET {SUPABASE}/auth/v1/user z uporabnikovim zetonom (identities[] s provider "apple";
// identity_data.sub / provider_id = Applov sub). user_metadata.sub v JWT NI vir: uporabnik ga piše sam (updateUser({ data })).
// Klic mora biti PRED izbrisom pri Supabase (potem identitet ni vec). Vrne seznam subov ([] = racun nima Applove identitete) ali null
// (neznano: izpad, rok, ne-200, slabo telo). Nikoli ne vrze. Rok IDENTITETE_ROK_MS (izbris podaljsa najvec za toliko).
const IDENTITETE_ROK_MS = 2500;
async function appleIdentitete(supabaseIss, apikey, token, rokMs = IDENTITETE_ROK_MS) {
  try {
    const r = await fetch(supabaseIss + "/user", { headers: { apikey, Authorization: "Bearer " + token }, signal: AbortSignal.timeout(rokMs) });
    if (!r.ok) return null;
    const u = await r.json();
    if (!u || !Array.isArray(u.identities)) return null;
    const subi = [];
    for (const i of u.identities) {
      if (!i || i.provider !== "apple") continue;
      for (const v of [i.identity_data && i.identity_data.sub, i.provider_id, i.id]) if (typeof v === "string" && v) subi.push(v);
    }
    return subi;
  } catch (_) { return null; }
}

// `sub` iz Applovega id_token (odgovor /auth/token, prejet neposredno od Appla prek TLS z nasim client_secret: podpisa ni treba preverjati,
// samo dekodiramo telo). Vrne niz ali null.
function subIzIdTokena(idToken) {
  try {
    const p = JSON.parse(Buffer.from(String(idToken).split(".")[1], "base64url").toString("utf8"));
    return p && typeof p.sub === "string" && p.sub ? p.sub : null;
  } catch (_) { return null; }
}

// Izmenjava kode in preklic. Vrne obljubo, ki se VEDNO razresi (true = preklicano, false = ne).
// `identitete`: rezultat appleIdentitete (seznam ali null). Neujemanje NE ustavi preklica (I74, ARCHITECTURE tocka 8): koda je od Apple ID-ja,
// ki ga je uporabnik pravkar potrdil na napravi; preklic zadene samo povezavo tega Apple ID-ja z Outlyjem. Zapise se samo opozorilo brez identifikatorjev.
async function preklici(n, koda, porociOpozorilo, identitete = null) {
  try {
    if (!n || !n.vklopljen || !koda) return false;
    const secret = clientSecret(n);
    const t = await klic(n, "/auth/token", { client_id: n.clientId, client_secret: secret, code: koda, grant_type: "authorization_code" });
    if (!t.ok) { zapisiNeuspeh("token", t, porociOpozorilo); return false; }
    const telo = t.telo || {};
    const sub = subIzIdTokena(telo.id_token);
    if (!Array.isArray(identitete) || !sub) {
      console.warn(`[apple] primerjava identitete preskocena (${!Array.isArray(identitete) ? "identitete racuna niso znane" : "id_token brez sub"}); preklic se vseeno izvede`);
    } else if (!identitete.includes(sub)) {
      const vrstica = `[apple] sub kode se ne ujema z identiteto racuna (Applovih identitet: ${identitete.length > 0 ? "vsaj ena" : "nic"}); preklic se vseeno izvede`;
      console.warn(vrstica);
      try { porociOpozorilo && porociOpozorilo(vrstica, "apple-preklic"); } catch (_) { /* nikoli */ }
    }
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

module.exports = { nastavi, veljavnaKoda, preklici, appleIdentitete, subIzIdTokena, clientSecret, ROK_MS, IDENTITETE_ROK_MS };
