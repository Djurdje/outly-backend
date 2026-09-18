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
4. ~~Healthchecks.io račun + secret `HC_URL` (#14)~~ — narejeno 18. 9. 2026 (ping potrjen v zagonu 35294068646).
   Ostane past spodaj: cron nadzora v resnici teče na 4–5 ur, zato mora biti Period/Grace v Healthchecks temu prilagojen.

## Predpostavke, ki jih je sprejel agent (brez Martina)

- **18. 9. 2026:** Healthchecks check naj ima **Period 6 h, Grace 3 h** (ne 15/20 min), dokler nadzor teče na
  GitHubovem cronu — glej past »GitHub cron teče na 4–5 ur«. S 15/20 min bi Healthchecks javljal lažen izpad po vsakem
  zagonu. Nastavitev je v Martinovi Healthchecks konzoli, agent je ne more spremeniti. Kdaj se vrne na 15/20:
  ko nadzor teče na zunanjem ponudniku (npr. UptimeRobot/Better Stack, brezplačno na 5 min) in ne na GitHub Actions.

- ~~**18. 9. 2026:** Workflow `Zascita` sproži zahtevo po oznaki tudi pri `orders` / `tickets`~~ — Martin je 18. 9.
  odločil »zoži«; ožji vzorec je v `DECISIONS.md` (Način dela).
- **18. 9. 2026:** Naloge, ki so bile v STATE.md, so razbite na Issues po tem, kdo jih mora narediti,
  ne po področju. Dve nalogi (Stripe) sta zato dve vrstici: račun (Martin) in koda (agent).

## Znane pasti (aktivne)

- **GitHub cron `*/15` teče na 4–5 ur, ne na 15 min.** Zagoni `Nadzor produkcije` z dogodkom `schedule` na `main`
  (Actions API, prebrano 18. 9. 2026 01:30 UTC): 17. 9. ob 00:45, 05:42, 10:26, 15:11, 19:02, 22:08 in 18. 9. ob 00:17 UTC —
  sedem zagonov v 24 urah. GitHub razporejene workflowe pri nizki dejavnosti repa zamika brez opozorila. Posledice:
  (1) izpad produkcije je lahko neviden do 5 ur, ne 15 min; (2) Healthchecks s Period 15 / Grace 20 min javlja lažen
  izpad ~35 min po vsakem zagonu (glej predpostavko zgoraj); (3) »vsakih 15 min« v `CLAUDE.md` in `nadzor.yml` opisuje cron,
  ne resničnosti. Rešitev od 18. 9. 2026: **UptimeRobot** (4 monitorji na 5 min, glej `ARCHITECTURE.md`, razdelek Nadzor);
  workflow ostane kot globlja preverba (401 brez žetona, Popravljalec, Healthchecks).
- **Agent na GitHubu JE lastnik.** Vsa dejanja iz sej Claude Code gredo prek računa `Djurdje` (API `get_me` 18. 9. 2026),
  ki je edini sodelavec repa z vlogo `admin`. Zato so oznaka `odobril-martin`, ruleset za `main` in »agent si oznake ne sme
  dodati sam« **dogovor, ne varovalo**: isti račun lahko oznako doda, ruleset izklopi ali potisne mimo. Trdo postane šele,
  ko seje tečejo prek ločenega računa z vlogo `write` (brez admin) in je ruleset brez izjem za bypass — glej #15.
- **`Zascita` še ni obvezen check** (#15): rdeč zagon merge-a tehnično ne ustavi, dokler ga Martin ne doda
  med required status checks. Do takrat mora agent pred merge-om ročno pogledati **oba** checka, ne samo `Testi`.
- **`jq` in `^`**: v `jq` je `^` zasidran na cel niz, ne na vrstico — vzorec čez vrstice diffa rabi `(?m)`.
  Brez tega filter tiho ne ujame ničesar in preverba je videti zelena. (Ujeto pri pisanju `zascita.yml`.)
- **Kako preveriti produkcijo brez izhodnega dostopa** (ker `curl` iz seje ne gre, glej naslednjo past):
  ročno sproži workflow **`Nadzor produkcije`** na veji `main` z vhodom `test=false` (to je prava preverba,
  ne simulacija) in preberi korak »Preveri produkcijo« — izpiše `OK <ime> (<status>)` za vseh sedem preverb.
  Uporabljeno po merge-u PR #27 (18. 9. 2026, zagon 35293761611): vse zeleno.
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
- **Obnova izvoza (`db/obnovi_izvoz.js`) zahteva POPOLNOMA prazno ciljno bazo** (nobena tabela razen
  `schema_migrations` ne sme imeti vrstic — namerno, brez izjeme, glej `_testi/test_obnova.js`). Migracija
  007 (`007_servisni_admin.sql`) pa v vsako sveže migrirano bazo vstavi servisni račun `agent@outly.si`.
  Zato takoj po `npm run migrate` na novi (prazni) bazi `users` NI prazna in obnova bo zavrnjena s
  »Cilj ni prazen«. Pred pravo obnovo (npr. na novi Render bazi) najprej `DELETE FROM users;` (ali samo
  vrstico `agent@outly.si`) na ciljni bazi — enako počne test. Dolgoročno: migracija 007 sama pravi
  »Ne pusti ga za vedno« — če se servisni račun kdaj odstrani/premakne izven migracij, ta past odpade sama.

## Kar nobeno orodje ne ve

- **Slike klubov v produkciji so ZA DEMO** (vzete s spletnih strani klubov). Pred pravim zagonom jih morajo
  zamenjati slike, ki jih dajo klubi sami — z dovoljenjem. Tega ne pove noben test.
- Demo podatki: 5 klubov (Cirkus, K4, Cvetličarna, Square, Nebo), ~15 dogodkov, kupec `gost@outly.si`,
  admin `martin…`, servisni `agent@outly.si`.
- **»Dela« pomeni: zelen Actions IN Martin preveril na napravi.** Dokler drugega ni, se piše
  »preverjeno s parse + pregledom tipov, na napravi ne«. Kaj čaka na napravo, je v #18.

## Način dela od 16. 9. 2026

Cloud seje Claude Code + PR-ji + CI; podrobnosti v `CLAUDE.md`.
