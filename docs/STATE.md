# Stanje — Outly (posodobi ob koncu vsakega sklopa)

Zadnja posodobitev: 2026-09-23 ("I'm in" / zanimanje za dogodek).

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

## Kje smo (23. 9. 2026, "I'm in" / zanimanje za dogodek)

Martin je 23. 9. 2026 narocil: na dogodku lahko uporabnik oznaci "I'm in" (zanimanje), prijatelji to vidijo
poleg tistih, ki dogodek ze imajo vstopnico ("going"). Backend (migracija 020, `_testi/test_zanimanje.js`, 38 testov, vsi zeleni):

- Nova tabela `event_interest (user_id, event_id, created_at)`, PK `(user_id, event_id)`, indeks po `event_id`.
  "Going" se **ne shranjuje nikjer** — izpelje se iz veljavne vstopnice, isti `IMETNIK` izraz kot v
  `/me/friends/plans` od 20. 9. Shranjuje se SAMO "interested".
- `PUT /events/:id/interest` (requireAuth): dogodek mora biti published, klub ne hidden, dogodek se ne sme
  biti koncal (isti pogoj `KONEC_DOGODKA` kot povsod drugod) — sicer 404 (ne obstaja/ni objavljen/klub skrit)
  ali 409 `{ error: "event_ended" }` (koncan). `INSERT ... ON CONFLICT DO NOTHING` (idempotentno).
  Odgovor `{ plan: "going" | "interested" }` — "going", ce ima uporabnik ze veljavno vstopnico (vstopnica
  prevlada, zanimanje se sicer vseeno zapise v bazo, a se v odgovorih ne kaze locено od going).
- `DELETE /events/:id/interest` (requireAuth): izbrise vrstico (idempotentno), `{ plan: "going" | null }`.
- `GET /events/:id` ima zdaj `neobveznaPrijava` (kot `GET /clubs/:id` od 22. 9.): novi polji `my_plan`
  (`"going" | "interested" | null`, brez zetona `null`), `friends_going` in `friends_interested`
  (`[{id, username, avatar_url}]`, samo prijatelji s `share_plans_with_friends = true`, invarianta I11;
  brez zetona prazna seznama). Prijatelj z vstopnico IN zanimanjem je samo v `friends_going`.
- `GET /me/friends/plans`: obstojece polje `friends` (= going) **nespremenjeno**. Novo polje `interested`
  (prijatelji SAMO z zanimanjem, isti I11 filter) in `my_plan` na vsakem dogodku. Dogodki, kjer ima vsaj en
  prijatelj SAMO zanimanje (brez ikogar going), so zdaj tudi v seznamu (unija `going ∪ interested`, `UNION` CTE).
  Filtri ostanejo: `published`, klub ne `hidden`, dogodek se ni koncal.
- `GET /me/plans` (requireAuth, novo): `{ events: [dogodek..., club_name, club_logo_url, my_plan] }` — moji
  lastni prihajajoci dogodki (going ali interested), za profil. Po `start_at` narascajoce.
- **Predpostavke agenta (Martin jih ni izrecno potrdil):** (1) "going" ostaja izpeljan iz vstopnice, ne
  shranjen — ce se kdaj izkaze, da je treba "going" tudi rocno oznaciti (npr. brez nakupa), je to nov stolpec/
  stanje, ne sprememba tega mehanizma. (2) Brisanje zanimanja ob nakupu vstopnice ni potrebno: vrstica v
  `event_interest` ostane, a se v odgovorih ne kaze vec locено (my_plan postane "going", oseba izgine iz
  `friends_interested`/`interested` in se pojavi v `friends_going`/`friends`) — ni razloga za DELETE ob
  nakupu. (3) Zanimanje za dogodek, ki se medtem koncal, ostane v `event_interest` (ni cistilnega opravila) —
  PUT na ze koncan dogodek vrne 409, obstojece vrstice pa preprosto izpadejo iz odgovorov (filter
  `KONEC_DOGODKA > NOW()` v `/me/friends/plans` in `/me/plans`; `GET /events/:id` ostane berljiv tudi za
  koncane dogodke, samo `my_plan` na njem se lahko kaze "interested", ce je uporabnik oznacil zanimanje pred
  koncem — to ni hrošč, samo zgodovinski podatek).
- **Backend PR #57 je v produkciji** (merge 23. 9. ~20:58 UTC, oznaka odobril-martin: Martin; Nadzor produkcije zagon #61
  na `main` `cbb9d11` zelen). **iOS PR #22** (outly-app) zdruzen takoj za njim (~21:00 UTC) -> TestFlight build. Vsebina iOS:
  krozno razkritje Home <-> Search/Profile, gumb->krog->kljukica pri prenosu (z vprasanjem) in nakupu (brez), sij na enem
  gumbu na zaslon, "I'm in" na dogodku, Friends plans kot vrstice po dogodku, View z Going/Interested. **Na napravi se NI
  potrjeno nic od tega** — seznam za Martina je v opisu PR-ja #22 (7 tock, tudi slovenski prevodi "gresta", "jih zanima").
- Odlocitve Martina 23. 9. (pogovor): nakup BREZ vprasanja pred placilom, prenos Z vprasanjem; moder gumb z belo kljukico
  (ne bel z modro); sij samo na gumbih, ki prinasajo nakup ali rast (Buy, Join them, Follow, Invite more, prijava), nikoli na
  opravilnih gumbih. Odprto iz iste seje (ni izbrano, ostane za naslednji krog): seznam piljenja P1-P21 (hrosci "Free" pri
  nil ceni, VALID v slovenscini, mnozine, prazna stanja, dvojni dotik, poenotenje radijev/gumbov) in animacije 1-15
  (skeletoni, fade-in slik, stil pritiska, haptika, zaporedno pojavljanje sekcij).

## Kje smo (22. 9. 2026, seja z Martinom)

Sklop »sledenje klubom + ended dogodki + popravki zaslonov«. Backend PR in iOS PR sta parna; iOS brez novega
backenda ne pade (vsa nova polja imajo privzetke), samo gumb Follow in posnetki ne delajo.

- **Backend (migracija 019) je v produkciji** — PR #55 združen 22. 9. 2026 ~21:15 UTC (oznaka `odobril-martin`: Martin),
  Render deploy uspel, `Nadzor produkcije` zagon #54 na `main` `7757193` zelen. Kaj je novega:
  - `club_follows` + `PUT|DELETE /clubs/:id/follow`, `GET /me/clubs/following`; `followers_count` v vseh odgovorih
    kluba, `is_following` v `GET /clubs/:id` (pot ima zdaj `neobveznaPrijava`).
  - `club_event_notifications` + `GET /me/club-events`, `POST /me/club-events/:id/seen`, `pending_club_events` v `GET /me`.
    Obvestilo nastane ob `POST /events` s `status=published` in ob `PATCH`, ki dogodek prvič objavi.
  - Dogodek: novo polje `lifecycle` (`upcoming` | `live` | `ended`) in `recap_video_url`; `time_status` NEspremenjen.
  - `GET /events?clubId=X&popular=true` → do 3 končani dogodki po `sold_count` (brez okna 7 dni, ki velja za `upcoming=false`).
  - `GET /business/events` ima `recap_allowed` (namig aplikaciji; pravilo uveljavi `PATCH /events/:id`).
  - `GET /me/friends/plans` odslej izloči **končane** dogodke (prej vse, ki so se začeli) — dogodek, ki nocoj teče, ostane.
- **Predpostavke agenta (Martin jih ni izrecno potrdil):**
  1. »Konec« brez vpisanega `end_at` je **začetek + 8 h**. Če se izkaže za prekratko/predolgo, se spremeni na enem mestu
     (`KONEC_DOGODKA` v `index.js`) — a takrat se spremeni tudi, kaj je »popular«.
  2. »Popular« = po **prodanih vstopnicah** (`sold_count`), ob izenačenju najnovejši. Klub, ki vstopnic ne prodaja prek
     Outlyja, ima vse pri 0 → popularni so trije najnovejši končani.
  3. `?popular=true` pokaže končane dogodke **starejše od 7 dni** (staro okno velja naprej za `?upcoming=false`).
     Brez tega posnetek dogodka izgine teden po dogodku, kar izniči namen.
  4. Obvestilo o novem dogodku je samo **zvonec v aplikaciji**; potisnega obvestila (APNs) še ni (čaka Martinov ključ).
- **iOS PR #19** (outly-app) združen takoj za backendom → TestFlight build. **Na napravi še NI potrjeno** nič od tega sklopa;
  seznam, kaj naj Martin preveri, je v opisu PR-ja #19.
- **Past (oblačna seja Claude Code):** omrežna politika oblačne seje **blokira `onrender.com`** (403 na CONNECT prek agent
  proxyja) in `download.swift.org`. Posledici: (1) produkcije po deployu se iz seje ne da preveriti s `curl` — namesto tega
  ročno sproži workflow `Nadzor produkcije` (`workflow_dispatch` na `main`, teče ~12 s) in preberi rezultat; (2) `swiftc -parse`
  za iOS ni mogoč — prevod preveri workflow `Gradnja iOS` na PR-ju (korak »Prevedi za simulator«), pred tem neodvisen pregled
  tipov. Zelen `Nadzor` pove, da produkcija odgovarja, **ne pa**, da streže ravno novo kodo (Render ob neuspelem deployu pusti
  staro instanco) — če je dvom, preveri novo polje v odgovoru (npr. `followers_count` v `GET /clubs`) s telefona ali z računalnika.

## Kje smo (21. 9. 2026, seja z Luko — Martin na dopustu)

Kaj je v produkciji oz. na TestFlightu in kaj še ni preverjeno na napravi. Ta razdelek se ob naslednjem sklopu prepiše.

- **Backend `main`** (Render, preverjeno z Nadzorom produkcije): migraciji **017** (obvestilo o prejeti vstopnici, PR #49) in
  **018** (ena oseba v več ekipah, glava `X-Outly-Club`, `GET /me` polje `clubs`, PR #52). Dokumenti: PR #50, #51.
- **iOS `master` = TestFlight build 66** (PR #16, #17, #18 v enem dnevu): meni obvestil brez nog + vrstica »X sent you a ticket«;
  »Invite more« 65 % in moder; Friends plans na novo (gumbi All/prijatelj samo pri ≥ 2 prijateljih, brez podvojenih/preteklih,
  kartica z Join them / View event); My friends z gumbom »Add friends« in listom za iskanje; **lastnikov profil je klubski**
  (OwnerProfileView, ClubSetupView za lastnika brez kluba); samo dva sloga vrstic; **Search/Profile nad zamegljenim Home**
  (drugi poskus — v buildu 64 je bil črn, ker NavigationStack prekrije ZStack; zdaj vsak zaslon riše `.outlyOzadje()` sam);
  Club info in sprememba gesla prek lista; My Clubs kaže vse klube (018), View nastavi `IzbraniKlub`.
- **Na napravi (Luka, build 66) še NI potrjeno:** zamegljeno ozadje pod Search/Profile in globlje; vabilo osebe, ki je že v
  K4, v drug klub + My Clubs z dvema kartama; Friends plans z dvema prijateljema; Club info brez zastoja. Build 64 je Luka
  preveril: lastnikov profil dela (glava je bila prevelika → popravljeno v 66), Friends plans se je »ne odziva« (vzrok: en
  sam prijatelj → All = fedo; v 66 gumbov pri enem prijatelju ni).
- **Čaka Martina:** (1) **push obvestila na telefon (APNs)** — Luka jih pričakuje; koda ni napisana, ker rabi APNs ključ iz
  Martinovega Developer računa in vklop Push Notifications pri podpisu; brez njega se ne da testirati. (2) Xcode Cloud za
  `master` → TestFlight (rabi Martinov Apple ID). (3) PR za `gradnja.yml` (concurrency + filter poti, oznaka). (4) potrditev
  treh odločitev z 21. 9. v DECISIONS (lastnikov profil, dva sloga vrstic, Revolut učinek) in »več klubov na osebo«.
- **GitHub Actions:** proračun za Actions je 20 $/mesec (bil 0 $ s Stop usage = da → past spodaj). Dogovor o varčevanju
  z macOS minutami je v razdelku »Način dela«.
- **Odprte najdbe brez posnetka:** Luka je na buildu 64 videl »pretekel dogodek« v Friends plans (Rock Night, pet. 25. 9. —
  ni pretekel; datum seje je bil pon. 21. 9.) in »podvojen dogodek« (v 66 aplikacija podvojene id-je izloči; strežnik jih
  ne bi smel vračati — če se ponovi, preveri `GET /me/friends/plans`).

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
- **22. 9. 2026 (zaprto):** politika zasebnosti **2.2** (razdelek »Prijatelji v aplikaciji«, podlagi prijatelji/načrti, vrstica za
  App Store) je **živa na outly.si/privacy-app** — outly_webpage PR #6, Martin dal DA v pogovoru 22. 9. Stikalo za deljenje
  načrtov ostane privzeto vklopljeno. Past: iz oblaka outly.si ni dosegljiv (egress), vsebino strani po objavi preveri Martin
  ali workflow `nadzor.yml` (ta preverja samo `/` in `/terms`).
- **20. 9. 2026 (prijatelji, backend PR #45, v produkciji):** Martin je naročil prijatelje (My friends, prošnje v obvestilih, »Your friends' plans«,
  prenos vstopnice prijatelju z izbiro iz seznama), na tri vprašanja pa ni odgovoril, zato velja: (1) prijatelja se najde **po
  uporabniškem imenu** (`GET /users/search`, predpona, samo potrjeni računi, največ 10, omejeno na 120/h); (2) stikalo
  `users.share_plans_with_friends` je **privzeto VKLOPLJENO** (sicer bi bil razdelek na domačem zaslonu pri vseh prazen), izklop v
  Preferences; (3) »View« odpre seznam dogodkov prijateljev, »Invite more« deli povezavo `https://outly.si` (brez `?ref=` — backend
  kod za točke ne pozna, živijo v Supabase). Politika zasebnosti (`privacy-app.html`) odstavek o prijateljih ima od
  22. 9. (različica 2.2, outly_webpage PR #6). Če Martin odloči drugače, so to tri majhne spremembe (in popravek politike).
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
