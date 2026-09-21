# Stanje — Outly (posodobi ob koncu vsakega sklopa)

Zadnja posodobitev: 2026-09-21.

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

- **20. 9. 2026 (iOS PR #14, v masterju, build 57):** Profil je vedno **osebni** (slika, ime, My Account), tudi za zaposlene; meni je
  za vse enak (My Clubs, Tickets, Payment, Support, About). Klubske funkcije (Dashboard, Scan tickets, Events, Team, Edit page)
  so **pod My Clubs → View** (MyClubDetailView), ne več globalno. »My Clubs« je seznam kartic, a ker backend dovoljuje eno
  članstvo na uporabnika (DECISIONS »en klub«), kaže 0 ali 1 kartico — če bo kdaj več klubov na osebo, je to backend
  odločitev, ne UI. Odstranjena izbira žanrov v Personal info. Kartice dogodkov: pas 50 pt, `.ultraThinMaterial.opacity(0.55)`;
  gumb za vstopnice na dogodku: bela obroba, malenkost večji.
- **20. 9. 2026 (iOS PR #15, v masterju, build 59) — prijatelji v aplikaciji so ŽIVI:** My Friends v profilu, **zvonec na domačem
  zaslonu odpre spustni meni** (vabila v ekipo + prošnje za prijateljstvo; prej je vodil na My Clubs), prenos vstopnice z izbiro
  prijatelja (e-naslov ostane), stikalo »Friends can see my plans« v Preferences, razdelek »Your friends' plans« pod In your area
  (krogi, Invite more = ShareLink outly.si, View). Na napravi še NI preverjeno (Martin, dva računa).
- **21. 9. 2026 (backend migracija 017 + iOS, isti dan):** obvestilo »X sent you a ticket« je **v aplikaciji vezano na
  dotik**: prebrano postane šele, ko uporabnik vrstico v meniju obvestil tapne (ne ob odprtju menija). Do takrat šteje
  na zvoncu. Obstoječi prenosi ob deployu dobijo `seen_at = NOW()` (migracija doda stolpec z DEFAULT in ga nato odstrani),
  da ne pade sto starih zvoncev. Meni obvestil nima več nog My Clubs / My Friends. iOS z novimi polji dela tudi na starem
  backendu (privzete vrednosti, napaka poti → prazen seznam); **backend PR mora biti v produkciji pred merge-om iOS PR-ja
  v master**, sicer testerji obvestil ne vidijo (ne pade). Backend PR rabi oznako `odobril-martin` (`db/migracije/**`).
- **21. 9. 2026 (backend migracija 018, več klubov na osebo):** aplikacija pošlje glavo `X-Outly-Club` samo tam, kjer uporabnik
  izbere klub (My Clubs → View); vsi drugi poslovni klici brez glave dobijo **prvo (najstarejše) članstvo**, kot doslej. Past:
  če ima oseba dve ekipi in aplikacija glave ne pošlje, ureja napačen klub tiho, brez napake — zato iOS nastavi
  `APIClient.currentClubId` ob vstopu v klub in ga ob izhodu pobriše. `DELETE /business/team/me` brez glave zapusti VSE ekipe.
- **21. 9. 2026 (iOS, Luka, Martin na dopustu) — predpostavke v PR-ju outly-app #17:** (1) lastnikov profil je klubski
  (DECISIONS 21. 9.); ce Martin odloci drugace, se v `ProfileView` odstrani veja `jeLastnik` (ena vrstica). (2) Prazna
  stanja: lastnik brez kluba → obrazec `ClubSetupView`, ki klice `POST /clubs`; backend na `GET /business/clubs/me`
  brez kluba vrne 404/403 — aplikacija oboje bere kot »ni kluba«. (3) Nov zaslon NE sme uporabiti
  `.background(Color.black…)`, ampak `.outlyOzadje()` (sicer v zavihku Search/Profile prekrije zamegljen Home).
  (4) Friends plans: aplikacija dodatno odstrani podvojene in pretekle dogodke (`vsi`), ceprav jih streznik ze filtrira —
  Luka je na buildu 62 videl podvojen dogodek in mrtev »Join them« (podvojen id v ForEach); vzrok na strezniku ni
  potrjen (posnetka ni bilo). Ce se ponovi, preveri `GET /me/friends/plans` za dva zapisa z istim `id`.
  (5) Naslov »Friends' plans« → »Friends plans« (Luka: apostrof moti); stari kljuc v Localizable.xcstrings ostane neuporabljen.
- **21. 9. 2026 (iOS, oblikovanje):** »Invite more« na domačem zaslonu je 65 % (krog 42 pt, napis 11 pt, ne 9 — Apple HIG
  spodnja meja), napis moder. »View« pri Your friends' plans odpre prenovljen zaslon: gumbi All + po en na prijatelja
  (izbrani moder), kartica z zatemnjenim plakatom, avatarji, »Join them« (nakup) in »View event«. My friends: moder gumb
  »Add friends« odpre list z iskanjem (iskanje ni več na seznamu); poslana prošnja = obrobljen pil »Requested«, dotik prekliče.
- **20. 9. 2026 (odprto):** politika zasebnosti za prijatelje je **osnutek v outly_webpage PR #6** in čaka Martinov DA — aplikacija
  načrte že deli, politika tega še ne omenja. Ne odlašati.
- **20. 9. 2026 (prijatelji, backend PR #45, v produkciji):** Martin je naročil prijatelje (My friends, prošnje v obvestilih, »Your friends' plans«,
  prenos vstopnice prijatelju z izbiro iz seznama), na tri vprašanja pa ni odgovoril, zato velja: (1) prijatelja se najde **po
  uporabniškem imenu** (`GET /users/search`, predpona, samo potrjeni računi, največ 10, omejeno na 120/h); (2) stikalo
  `users.share_plans_with_friends` je **privzeto VKLOPLJENO** (sicer bi bil razdelek na domačem zaslonu pri vseh prazen), izklop v
  Preferences; (3) »View« odpre seznam dogodkov prijateljev, »Invite more« deli povezavo `https://outly.si` (brez `?ref=` — backend
  kod za točke ne pozna, živijo v Supabase). Politika zasebnosti (`privacy-app.html`) mora dobiti odstavek o prijateljih —
  pravni dokument, čaka Martinov DA (ločen PR na spletni strani). Če Martin odloči drugače, so to tri majhne spremembe.
- **18. 9. 2026:** Healthchecks check naj ima **Period 6 h, Grace 3 h** (ne 15/20 min), dokler nadzor teče na
  GitHubovem cronu — glej past »GitHub cron teče na 4–5 ur«. S 15/20 min bi Healthchecks javljal lažen izpad po vsakem
  zagonu. Nastavitev je v Martinovi Healthchecks konzoli, agent je ne more spremeniti. Kdaj se vrne na 15/20:
  ko nadzor teče na zunanjem ponudniku (npr. UptimeRobot/Better Stack, brezplačno na 5 min) in ne na GitHub Actions.

- ~~**18. 9. 2026:** Workflow `Zascita` sproži zahtevo po oznaki tudi pri `orders` / `tickets`~~ — Martin je 18. 9.
  odločil »zoži«; ožji vzorec je v `DECISIONS.md` (Način dela).
- **18. 9. 2026:** Naloge, ki so bile v STATE.md, so razbite na Issues po tem, kdo jih mora narediti,
  ne po področju. Dve nalogi (Stripe) sta zato dve vrstici: račun (Martin) in koda (agent).
- **20. 9. 2026 (iOS, PR #10):** »My preferences« (žanri, razdalja, starost, cena) so shranjene **samo na napravi**
  (`UserPreferences`, @AppStorage); backend jih ne pozna, sinhronizacije med napravami ni. Če se kdaj želi
  strežniško, je to nov stolpec/pot na `/me` (samo dodajanje). Zvonec na domačem zaslonu šteje **čakajoča vabila
  v ekipo** (`Me.pendingInvites`), ker drugih obvestil (APNs) ni; značka »1« ali »1+«.
- ~~**20. 9. 2026 (iOS, PR #10):** Sistemski `TabView` je zamenjan z `ZStack` + lastno vrstico `OutlyTabBar`~~ —
  vrnjeno še isti dan v PR #11 (`6810def`): spet sistemski `TabView`, `OutlyTabBar` umaknjen.
- **20. 9. 2026 (iOS, PR #12):** Filtri na domačem zaslonu: Distance, Age range in Entry price so drsniki **od–do**
  s histogramom **dejanske** porazdelitve prihajajočih dogodkov (razdalja do kluba iz lokacije naprave, `min_age`,
  `ticket_price_cents`); histogram se prilagaja ostalim aktivnim filtrom. `EventFilters` ima zato tudi
  `minDistanceKm`. Histogram razdalje je prazen brez dovoljenja za lokacijo — to ni hrošč. Stikalo »Use my
  preferences« ob **izklopu** vrne žanre, razdaljo, starost in ceno na privzete vrednosti (mesto ostane) in si
  stanje zapomni v filtrih (`izMojihNastavitev`). Vse to je samo v aplikaciji — backend ne pozna filtrov ne preferenc.
  Kartice dogodkov: cena v modrem gumbu na temno prosojnem pasu; stran dogodka: en sredinski moder okvir s ceno
  (ozadje 65 %), brez belega gumba »Get tickets« — logika nakupa nespremenjena.

## Znane pasti (aktivne)

- **`[skip ci]` na backend PR-ju blokira merge** (21. 9. 2026, PR #51): GitHub preskoči `Testi` (dogodek `pull_request`),
  `Zascita` (`pull_request_target`) pa teče; zaščita veje `main` zahteva `Testi`, zato PR ostane »Expected — waiting«.
  Backend testi so Linux in stanejo ~1 min — `[skip ci]` tam ni vreden nič. Popravek: nov push brez oznake.
  **GitHub oznako išče v celotnem sporočilu commita, ne samo v prvi vrstici** — tudi stavek »past: [skip ci] …« v opisu
  jo sproži (zgodilo se 21. 9., dvakrat). V sporočilih commitov to oznako omenjaj samo opisno, brez oglatih oklepajev.
- **GitHub »Budgets and alerts« ima privzeto proračun 0 $ za Actions s »Stop usage: Yes«** (najdeno 21. 9. 2026, Luka):
  ob porabljeni brezplačni kvoti (2 000 min) se ustavi **vse** — tudi backend `Testi` (merge v produkcijo brez zelenega CI ni
  mogoč) in `Nadzor produkcije` (izpad nevidno). 21. 9. spremenjeno na **20 $/mesec** (Stop usage ostane Yes kot varovalo,
  realna poraba ~5–15 $). Proračun se šteje na obračunski cikel (1. v mesecu); poraba pred nastavitvijo se ne šteje.
  Ostali štirje (Codespaces, Packages, Git LFS, AI Credit) namerno ostanejo 0 $.

- **TestFlight podpis je odvisen od certifikata v GitHub secrets** (od 20. 9., outly-app PR #13): `IOS_DEV_CERT_P12` +
  `IOS_DEV_CERT_PASSWORD` (CI-jev lasten »Outly CI« Apple Development certifikat, velja do ~20. 9. 2027). Če ga kdo na
  developer.apple.com prekliče ali poteče, korak »Podpisan arhiv« pade — PR-ji ostanejo zeleni (samo prevod). Popravek: nov
  CSR (OpenSSL, tudi na Windowsu) → nov .p12 → zamenjava obeh secrets. Brez teh secrets se TestFlight korak preskoči z
  opozorilom, ne pade. Zgodovina: DECISIONS (Infrastruktura, 20. 9.), INCIDENTI 2026-09-20.
- **Swift toolchain v oblačni seji ni dosegljiv** (20. 9.): `download.swift.org` in GitHub *releases* (tudi swiftwasm)
  vračata 403 prek egress proxyja; `swiftc -parse` iz iOS `CLAUDE.md` tam ni izvedljiv. Nadomestilo: `type-checker`
  subagent + prevod za simulator na PR-ju (workflow `Gradnja iOS`, ~2 min). Enako velja za `outly.si` in
  `onrender.com` (glej past zgoraj) — spletno stran po objavi preveri Martin v brskalniku, backend prek ročnega zagona
  workflowa **Nadzor produkcije** (`workflow_dispatch` na `main`; 20. 9. zagon 29 zelen po docs mergu #33).
- **Headless preverjanje outly.si v oblaku** (20. 9.): `cdn.jsdelivr.net` (supabase-js UMD) ni dosegljiv, zato
  `window.supabase` ne obstaja in `auth.js` tiho izpusti ploščo — v Playwright testu je treba **stubati tudi CDN
  skript** (minimalen `window.supabase.createClient` z `auth.getSession`, `onAuthStateChange`, `rpc`, verižni `from()`),
  ne samo REST. Playwright: `npm i playwright` v scratchpadu + `executablePath` `/opt/pw-browsers/chromium-*/chrome-linux/chrome`.
  Skript je zapisan kot skill (`.claude/skills/headless-preverjanje-strani`, čaka `odobril-martin`).
- **Splet: razred `.points` je kartica točk v profilu** (`auth.js`, centrirana, obrobljena) — razdelek na strani je
  `pointsSection` / `#points`. Nov razdelek s tem razredom bi podedoval centriranje.
- **Docs-only merge v `main` vseeno sproži Render deploy** (`npm run migrate && npm start`); nevarnosti ni, a ~60 s
  restarta backenda se zgodi.

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

- **Od 21. 9. 2026 — varčevanje z macOS minutami GitHub Actions** (Luka, ker je kvota 2 000 min/mesec pri 90 %;
  macOS se šteje ×10, nad kvoto ~0,08 $/pravo minuto). Dogovor, dokler ne pride Xcode Cloud (čaka Martina, glej spodaj):
  1. **En merge v `master` na delovni dan** oz. na zaključen sklop (danes: 4 točke skupaj v enem PR-ju). Vsak merge = build
     pri testerjih (~10 min macOS = 100 min kvote).
  2. **Push na PR vejo šele, ko je sklop končan in pregledan s `type-checker`** — cilj en push na PR (vsak push = ~4 min = 40 kvote).
  3. Vmesni pushi (da se delo ne izgubi) na **iOS** veji s **`[skip ci]`** v sporočilu commita; zadnji push pred
     merge-om brez tega, da je PR zelen. **Na backendu `[skip ci]` NE uporabljaj** (past spodaj).
  4. Backend PR-ji so Linux (×1) — tam ni treba varčevati.
  5. Meja: ne zbirati več kot en dan ali več nepovezanih stvari v en PR (če na telefonu ne dela, se ne ve, kaj je krivo).
  Ko bo Martin nazaj: PR v `gradnja.yml` (preklic zastarelih gradenj `concurrency`, PR gradnja samo ob spremembi Swift/projekta) —
  rabi `odobril-martin`; in **Xcode Cloud** samo za `master` → TestFlight (25 h/mesec brezplačno v Developer Programu,
  PR prevod ostane na GitHubu, da agent vidi dnevnike). Rabi Martinov Apple ID (Individual račun nima članov ekipe).

Cloud seje Claude Code + PR-ji + CI; podrobnosti v `CLAUDE.md`.

- **Od 20. 9. 2026 dela na projektu Luka** (dostop do vseh treh repozitorijev in storitev), na **MacBooku z Xcodom**.
  To pomeni: iOS gradnjo in preverjanje na napravi/simulatorju lahko naredi lokalno, ne samo prek Actions/TestFlighta.
  Agent v oblačni seji Xcoda še vedno nima (past »Swift toolchain v oblačni seji ni dosegljiv«) — pravilo
  »veja + PR + zelen Actions« ostane, lokalni Xcode je dodatna preverba, ne nadomestilo.
