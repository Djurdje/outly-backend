"use strict";
/**
 * Casovne meje HTTP povezav (issue #139, korak 2).
 *
 * Node privzeto zapre mirujoco vzdrzevano povezavo po 5 s (keepAliveTimeout). Renderjev proxy pa povezave do storitve
 * ponovno uporablja dlje: ce Node povezavo zapre prej, ko proxy mislil, da je se odprta, proxy ob naslednjem zahtevku
 * zadene zaprto povezavo (ECONNRESET -> 502) ali mora odpreti novo, ki ob navalu caka v vrsti za sprejem (do ~3 s;
 * za vratarjev sken to ni sprejemljivo). Render za Node priporoca keepAliveTimeout nad mirovalnim rokom proxyja (120 s); vir: https://render.com/docs/troubleshooting-deploys, razdelek »502 Bad Gateway« (tudi v #139).
 *
 * Node zahteva headersTimeout > keepAliveTimeout (sicer se vzdrzevana povezava lahko zapre sredi prejemanja glav);
 * headersTimeout = keepAliveTimeout + 1 s. requestTimeout (privzeto 300 s) mora ostati NAD headersTimeout, zato je zgornja
 * meja KEEPALIVE_MS 280 s. Pocasen odjemalec je pred storitvijo ze v proxyju (ta preda zahtevek sele, ko ga ima), zato
 * daljsi headersTimeout ne odpira slowloris proti procesu.
 */
const PRIVZETO_MS = 120000;
const NAJVEC_MS = 280000;

/** `surovo` je vrednost KEEPALIVE_MS (niz ali undefined). Neveljavno, prazno ali 0 -> privzeto (0 bi v Node izklopilo rok). */
function keepAliveIzOkolja(surovo, { opozori = console.error } = {}) {
  if (surovo === undefined || surovo === "") return PRIVZETO_MS;
  const n = Number(surovo);
  if (!Number.isFinite(n) || n < 1) { opozori(`[okolje] KEEPALIVE_MS="${surovo}" ni veljavno, uporabljam ${PRIVZETO_MS}`); return PRIVZETO_MS; }
  return Math.min(Math.floor(n), NAJVEC_MS);
}

/** Nastavi meje na http.Server; vrne uporabljene vrednosti (za dnevnik in teste). */
function nastaviMejePovezav(streznik, surovoKeepAlive, moznosti) {
  const keepAliveMs = keepAliveIzOkolja(surovoKeepAlive, moznosti);
  streznik.keepAliveTimeout = keepAliveMs;
  streznik.headersTimeout = keepAliveMs + 1000;
  return { keepAliveMs, headersMs: streznik.headersTimeout, requestMs: streznik.requestTimeout };
}

module.exports = { nastaviMejePovezav, keepAliveIzOkolja, PRIVZETO_MS, NAJVEC_MS };
