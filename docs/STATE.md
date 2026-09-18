# Stanje — Outly (posodobi ob koncu vsakega sklopa)

Zadnja posodobitev: 2026-09-18.

Ta datoteka hrani **samo tisto, česar se ne da prebrati drugje**. Kar je drugje, je tam merodajno:

| Vprašanje | Kje piše | Ne v STATE.md |
|---|---|---|
| Kaj je še odprto, kdo mora kaj narediti | **GitHub Issues** (`agent` = agent, `martin` = Martin) | ne prepisuj seznama nalog |
| Ali testi tečejo | **Actions → `Testi`** ob vsakem PR-ju | ne prepisuj števila testov |
| Ali produkcija dela | **Actions → `Nadzor produkcije`** (vsakih 15 min) + `https://outly-backend-roy3.onrender.com/clubs` | ne prepisuj »dela/ne dela« |
| Kaj se je spremenilo | **zgodovina PR-jev in commitov** | ne piši dnevnika po gradnjah |
| Zakaj je nekaj tako | `docs/DECISIONS.md` | |
| Kaj se ne sme zgoditi in kaj to preprečuje | `docs/ARCHITECTURE.md`, »Poslovne invariante« | |
| Kaj je že enkrat padlo | `docs/INCIDENTI.md` | |

Ostane torej: pasti (grabljice, na katere je nekdo že stopil), predpostavke, ki jih je agent sprejel sam,
in stvari, ki jih nobeno orodje ne ve.

## Odprte naloge

**Seznam je v GitHub Issues**, ne tukaj: <https://github.com/Djurdje/outly-backend/issues>

- oznaka **`martin`** — potrebuje človeka: denar, nastavitve računov (Render, Apple, Stripe, Healthchecks),
  preverjanje na telefonu, pravne odločitve.
- oznaka **`agent`** — agent lahko naredi sam, brez Martina.

Vrstni red po nujnosti (samo kar ima rok ali blokira drugo):

1. **Render baza na plačljivi paket pred 7. 10. 2026** — po tem datumu se izbriše (#12).
2. Stripe račun (#16) blokira tehnično plačilno pot (#19).
3. Oznaka `odobril-martin` + `Zascita` med obvezne checke (#15) — dokler tega ni, zaščita ne ustavi ničesar.
4. Healthchecks.io račun + secret `HC_URL` (#14) — dokler ga ni, izpad samega nadzora ni viden.

## Predpostavke, ki jih je sprejel agent (brez Martina)

- **18. 9. 2026:** Workflow `Zascita` sproži zahtevo po oznaki tudi pri navadnih spremembah `index.js`,
  ki se dotaknejo besed `orders` / `tickets` (te so v kodi pogoste). Raje preveč alarmov kot premalo;
  če Martina to preveč ustavlja, se vzorec v `.github/workflows/zascita.yml` zoži na `requireRole|requireClub|stripe`.
- **18. 9. 2026:** Naloge, ki so bile v STATE.md, so razbite na Issues po tem, kdo jih mora narediti,
  ne po področju. Dve nalogi (Stripe) sta zato dve vrstici: račun (Martin) in koda (agent).

## Znane pasti (aktivne)

- **Seje Popravljalca nimajo izhodnega dostopa**: egress proxy vrne 403 »organization policy« za
  `outly-backend-roy3.onrender.com`, `outly.si`, `supabase.co` in `ntfy.sh`. Neposreden `curl` iz postopka
  v `CLAUDE.md` tam **ni izvedljiv** — stanje produkcije se potrdi posredno prek zgodovine Actions
  (»Nadzor produkcije«, veja `main`). Če to ni namerno, je treba tem sejam odpreti izhod.
- **Lokalni testi in SSL**: `index.js` in `db/migrate.js` izklopita SSL samo, če `DATABASE_URL` vsebuje niz
  `localhost`. Z `127.0.0.1` migracije padejo z »The server does not support SSL connections«.
  Uporabljaj `postgres://postgres@localhost:5432/outly`.
- **iOS `.refreshable`**: vedno `await Task { await load() }.value`, nikoli `await load()` neposredno —
  sicer SwiftUI prekine nalogo ob prvi spremembi stanja in uporabnik vidi »Connection problem«.
- **iOS jezik**: nov ključ v `Outly/Localizable.xcstrings` ne sme trčiti z drugim po veliki/mali črki ali ločilih —
  Xcode 26 generira Swift simbole iz ključev in gradnja pade. (`STRING_CATALOG_GENERATE_SYMBOLS = NO` to izklopi,
  a preveri, če se kdaj spet vklopi.)
- **iOS Combine**: nova datoteka z `ObservableObject`/`@Published` rabi eksplicitno `import Combine` —
  Xcode 26 ga prek SwiftUI ne uvozi več samodejno.
- **macOS minute v Actions** se štejejo ×10: ena iOS gradnja z uploadom ~8–10 min = 80–100 od 2000 brezplačnih
  minut/mesec (~20 pushev v `master`). PR sproži samo prevod za simulator (~4 min).
- **Figma MCP**: dnevna omejitev klicev (Starter) — ogled prek figma.com v brskalniku.
- Ostale pasti (AsyncImage brez okvirja, gnezden NavigationStack, pg BIGINT, Resend `{error}`, JSONB vs ARRAY)
  so v `CLAUDE.md` tega repa in iOS repa.

## Kar nobeno orodje ne ve

- **Slike klubov v produkciji so ZA DEMO** (vzete s spletnih strani klubov). Pred pravim zagonom jih morajo
  zamenjati slike, ki jih dajo klubi sami — z dovoljenjem. Tega ne pove noben test.
- Demo podatki: 5 klubov (Cirkus, K4, Cvetličarna, Square, Nebo), ~15 dogodkov, kupec `gost@outly.si`,
  admin `martin…`, servisni `agent@outly.si`.
- **»Dela« pomeni: zelen Actions IN Martin preveril na napravi.** Dokler drugega ni, se piše
  »preverjeno s parse + pregledom tipov, na napravi ne«. Kaj čaka na napravo, je v #18.

## Način dela od 16. 9. 2026

Cloud seje Claude Code + PR-ji + CI; podrobnosti v `CLAUDE.md`.
