# Stanje — Outly (posodobi ob koncu vsakega sklopa)

Zadnja posodobitev: 2026-10-09 (organizatorji brez prizorišča, migracija 037; prej 2026-10-08: obvestilo o vabilu na guest listo, migracija 036; guest lista, migracija 035; prej 2026-10-05: nakup brez računa; prej 2026-10-02: prenesena vstopnica brez seriala v kupčevem pogledu #124; neujet await v ročnikih #129; idempotentni ključ nakupa #112; zgodovina do 2. 10. premaknjena v arhiv; meja 200 vrstic, outly-hq pravilo 5).

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

**Zgodovina** (zaključeni sklopi, dnevniki sej, stari načrti in daljše prvotno besedilo pasti do 2. 10. 2026) je v
[`docs/arhiv/STATE-do-2026-10-02.md`](arhiv/STATE-do-2026-10-02.md) — ni merodajna. Ta datoteka ima **največ 200 vrstic**;
kar ni več past, gre v nov arhiv `docs/arhiv/STATE-do-<datum>.md` (zadnji: [`STATE-do-2026-10-02d.md`](arhiv/STATE-do-2026-10-02d.md)).

## Odprte naloge

**Seznam je v GitHub Issues**, ne tukaj: <https://github.com/Djurdje/outly-backend/issues>

## Spremljanje napak

- **Backend:** Render logi (`list_logs` na `srv-d5fuiovgi27c73e4boq0`, filter `*rror*`), brez Sentryja. Request logov (500)
  Render za to storitev ne vrne — vidno je samo, kar koda izpiše. **iOS:** sesutja zbira TestFlight.
- **Spletna aplikacija:** Sentry `outly-hd` (EU) / `outly-webapp`, `webapp/porocilo.js` brez SDK, največ 5 dogodkov na nalaganje,
  DSN 100/uro, IP se ne hrani (politika zasebnosti 2.4). Ob dvigu `RAZLICICA` v `webapp/sw.js` uskladi `RAZLICICA` v `porocilo.js`.
- **Brevo (Supabase Auth SMTP: potrditve, kode za prijavo) je na paketu Free = 300 mailov/dan.** Ob več prijavah na dan kode
  ne pridejo in prijava ne dela. Pred javnim zagonom odloči Martin (plačljiv paket ali drug ponudnik).

## Render (od 30. 9. 2026; paketa v ARCHITECTURE, Produkcija)

- **Zmogljivost (lokalno, ne napoved produkcije):** `orodja/obremenitev.mjs` + `_testi/test_obremenitev.js`; z bazo 0,1 CPU je streha javnih poti ~90 req/s (ozko grlo je baza); proti produkciji ni merjeno (#89, I16). **Past (#139, 2. 10.):** med navalo 300 nakupov + 1000 bralcev (3b) NOVA TCP povezava skena caka 0,4-3,2 s (CI; stara koda 3 od 3 prvih zagonov rdeca), vzdrzevana (keep-alive) pa ne (p95 0,25-0,41 s, max 0,69 s, 9 zagonov). Jedro ni zavrglo nobene povezave (ListenOverflows/Drops/TCPReqQFullDrop/TCPSynRetrans = 0). **Mehanizem je DELOVNA HIPOTEZA** (mikro poskus + casovnica CI, jobi 111072748721 in 111071140689; komentar v #139): Node sprejme ~1 povezavo na obdelan zahtevek, ko je zanka zasedena. Test skenira prek vzdrzevane povezave, nova je sonda (< 8 s); tveganje v produkciji: sken brez proste povezave (#139 odprt). **Meritev v produkciji (#139, korak 1):** Render logi, iskanje `[povezave]` (`list_logs` na `srv-d5fuiovgi27c73e4boq0`): vrstica na 60 s samo ob prometu, `novih N, zahtevkov M, odprtih K, zamik zanke p99/max ms` (`dnevnik_povezav.js`, izklop `DNEVNIK_POVEZAV_MS=0`). Beri SAMO okna, kjer je zahtevkov bistveno vec kot health checkov (Render health check, Nadzor, Healthchecks: vsak lahko 1 nova povezava + 1 zahtevek; nocna okna dajo novih ~ zahtevkov tudi ob bazenu): novih ~ zahtevkov = proxy odpira novo povezavo za vsak zahtevek; novih << zahtevkov = bazen vzdrzevanih; zamik max >> 100 ms = zasicena zanka.
- **Zunanji dostop do baze je zaprt** (Inbound IP Rules `outly-db` prazne; backend gre po notranjem omrežju, `10.x`). psql /
  pgAdmin z External Database URL ne dela: dodaj svoj IP (in ga odstrani) ali Render Shell. Pravili `0.0.0.0/0` na ravni
  workspacea in okolja ostaneta (veljata tudi za web servis) — ne zapiraj.
- **Health Check Path = `/healthz`** (200 / 503 ob nedosegljivi bazi, `_testi/test_zdravje.js`; lasten pool `zdraviPool`; 503 tudi ob >60 s zastoju glavnega poola ali skenPool (nobena povezava se ne vrne), I10); Render novo kodo spusti v promet
  šele, ko odgovori. Interni klici health checka niso v request logih (prazni logi so pričakovani).

## Cloudflare Browser Cache TTL = 4 h (29. 9. 2026)

- Vse statične datoteke outly.si dobijo `max-age=14400`; `Cache-Control: no-cache` iz `_headers` NE velja (HTML ima `max-age=0`).
  Spletna aplikacija se brani sama (`outly_webpage/CLAUDE.md`), **landing ne**: `script.js`, `auth.js` ... so lahko do 4 h stari.
  Priporočilo Martinu (nastavitev računa): Caching → Browser Cache TTL = »Respect Existing Headers«.

## Sken brez povezave (QR v2; ARCHITECTURE »Sken brez povezave«, invarianta I14)

- Past: ob zamenjavi `QR_SECRET` se spremeni tudi javni ključ — telefon mora ključ ob vsaki sinhronizaciji primerjati po `kid`.
- Idempotentnost skena brez povezave je zaznamek `batch|<device_id>|<client_scan_id>` v `tickets.scan_device` (stolpec sicer
  hrani user-agent online skena; nihče ga ne bere) — brez migracije. `device_id` in `client_scan_id` morata biti naključna (UUID).
- Znane omejitve: (1) dva telefona brez povezave lahko spustita isto vstopnico (`already_used` šele ob sinhronizaciji; zapisnika
  konfliktov ni — rabi tabelo/migracijo). (2) Vstopnica, kupljena po prenosu seznama, ima veljaven podpis, a je ni na seznamu.
  (3) `used_at` s telefona velja le v oknu [največ(nastanek vstopnice, začetek dogodka − 12 h), zdaj], `scanned_at` 2020 … zdaj + 1 dan.
- **`QR_SECRET` na Renderju ni nastavljen**: kode podpisuje rezervna `JWT_SECRET` (>= 32 znakov; INCIDENTI 2026-10-01). Ob kratki
  ali prazni skrivnosti backend ob zagonu samo opozori (`console.error`). Nastavitev/zamenjava razveljavi vse QR kode — odloči Martin.
- **Okno skena na strežniku (8. 10. 2026, I25):** nova vrednost `result: "not_today"` v `POST /business/tickets/scan` (409, `message` »This ticket is not for today's event.«, `ticket` kot pri drugih zavrnitvah) in kot element `scan-batch` (`used_at: null`, vstopnica ostane `valid`).
  Odjemalca: splet (#42) `not_today` pozna (`naslovRezultata`); iOS #68 ima lokalno sodbo `nijeZaDanes`, strežniški `not_today` pa v `SkenPrikaz.iz(streznik:)` je padel v `default` (rdeče »INVALID CODE«) – popravljeno v outly-app #69 (`case "not_today"` -> »NOT TODAY'S EVENT«, tudi v `razlogKonflikta`). Starejše gradnje: rdeče »REFUSED« / konflikt, brez sesutja.
  Past (ura): `scan-batch` okno presoja po `scanned_at`, zato telefon s krivo uro (> 12 h) dobi `not_today` za vse skene brez povezave. Že nekajurna napaka ure
  ob skenu blizu nastanka vstopnice (`scanned_at` pred `created_at` -> velja zdaj) ali v zadnjih urah okna lahko da `not_today`, če se telefon sinhronizira po zaprtju okna.
  Past (večdnevni dogodek): brez vpisanega `end_at` je okno `start − 12 h … start + 18 h`; večdnevni dogodek mora imeti `end_at`, sicer vrata drugi dan vrnejo `not_today`.
- Dostop: `scan-key` in `scan-list` vidijo vse vloge v klubu (tudi vratar) — vratar tako dobi seznam imen imetnikov vstopnic; e-naslovov ni.

## VIP mize (od 1. 10. 2026; ARCHITECTURE »VIP mize«, I13; VIP 18+ od 2. 10., I8, DECISIONS)

- Backend (#84), iOS (outly-app #43) in splet (outly_webpage #22) so združeni; urejevalnik tlorisa je samo na spletu.
- **Past:** `GET /events/:id` `vip_enabled` je `true` samo, ce je VIP vklopljen IN ima dogodek vsaj eno vklopljeno aktivno mizo
  (`GET /business/events/:id/vip` `enabled` pa je surova stikalna vrednost dogodka). Nakup mize in nakup vstopnic delita
  omejevalnik "nakup" (20/uro na IP). `PUT /business/vip` zaklene vrstico kluba z `FOR NO KEY UPDATE` (ne `FOR UPDATE`): nakup mize
  bere klub prek tujega kljuca in bi se s polnim zaklepom zaciklal (mrtva zanka).
- `PUT /business/events/:id/vip` id arhivirane mize TEGA kluba tiho preskoči (400 samo za tuje); javni `GET /events/:id/vip` obdrži
  prodano mizo tudi po izklopu/arhivu (`available: false`); `POST .../orders` sprejme `expected_price_cents` (409 ob spremembi cene).
- **Vračil miz ni** (poti ni; `DELETE /events/:id` z naročili dogodek odpove, mize ostanejo pri kupcih); Stripe poti za mize ni (#19).
- **Past:** vsak paket velja za alkohol; brezalkoholnih paketov ni mogoce oznaciti, dokler ne pride stolpec (DECISIONS 2. 10.).
- **VIP 18+ na odjemalcih še ni:** iOS in splet polja `package_min_age` (lahko `undefined` na starem backendu — privzeto 18) še ne
  kažeta. 403 sta navadno besedilo (kot pri `min_age`); odjemalec starosti ne preverja sam.
- **Rezervacija mize po telefonu (4. 10., migracija 032; ARCHITECTURE »VIP mize«, I13, DECISIONS 4. 10.):** novo polje `hold` pri mizi v `GET /business/events/:id/vip` (ios-dev/web-dev: gumba Rezerviraj/Sprosti). **Past:** po `DELETE` na drugi instanci nakup do 3 s dobi 409.

## Javni predpomnilnik (#114, ARCHITECTURE »Javni predpomnilnik«, I17; odločitev agenta, Martin je ni potrdil)

- `/events`, `/clubs`, `/events/:id`, `/clubs/:id` so 3 s v pomnilniku; zapis ga izprazni, mimo API-ja (SQL, migracija, druga instanca) zaostane do 3 s.
  Dnevnik `[predpomnilnik] 60 s: …` kaže zadetke/razveljavitve; izklop: `JAVNI_PREDPOMNILNIK_MS=0`. Nov javni GET, odvisen od uporabnika, NE sme vanj.
- Za iOS/splet (neobvezno): `GET /events?lite=true` brez `description` (ključ manjka; model naj ga ima neobveznega), `ETag`/304.

## Spletna aplikacija (outly.si/app; podrobnosti v `outly_webpage/CLAUDE.md`)

- **Ni javna** (Martin 29. 9.: »da lahko jaz prvo vse preverim«): dosegljiva samo z neposrednim URL-jem, `noindex`.
  **Gumba na outly.si ne dodajaj, dokler Martin ne reče** — to je hkrati javna objava.
- **Osnutek politike zasebnosti** za spletno aplikacijo (`docs/osnutki/zasebnost-spletna-aplikacija.md`, tudi kamera za skener)
  NI objavljen, čaka Martinov DA; popravi netočno alinejo §11 (žeton v brskalniku ni v »varni shrambi sistema«).
- Kontrast: bel napis na modrem gumbu (#4C76FF) 3,35–3,93 (WCAG AA 4,5); barva znamke — samo Martin. Modro besedilo na spletu #6A8CFF.
- `GET /business/events/:id/tickets` vrne podpisan `qr` vseh vstopnic vsem vlogam v klubu (iOS enako); splet ga hrani samo v pomnilniku.
- **Past (backend, obstojeca):** `klubUporabnika(uid, zeljeni)` za lastnika z VEC klubi vrne samo prvega (`ORDER BY id LIMIT 1`);
  lastnik z drugim klubom v glavi `X-Outly-Club` dobi 404. Danes ima vsak lastnik en klub - ob drugem klubu to popraviti.
- **Past (splet):** `PATCH /me` vrne samo `POLJA_UPORABNIKA` (brez `clubs`, `pending_*`) - odjemalec mora zdruziti s
  trenutnim profilom ali znova poklicati `GET /me` (iOS po avatarju klice `GET /me`).
- MapLibre 5 nima več `maplibregl.supported()`; MapLibrov CSS (naložen pozneje) prepiše `position` platna — pravila zemljevida
  imajo zato višjo specifičnost (`.karta.maplibregl-map`).
- **Odprte najdbe pregleda faze 1** (29. 9., še brez Issueja): CSP velja samo za `/app` (seja v localStorage je skupna z vsem
  outly.si); `img-src https:` (poljuben https plakat/logo); `ticket_url`, `website`/`logo_url` brez preverbe `^https://` na strežniku
  (splet filtrira z `varenUrl`, iOS ne).

## Stripe plačila (od 3. 10. 2026; issue #19, `placila_stripe.js`, DECISIONS 3. 10., I19)

- Sandbox račun »Outly sandbox« (Martinov Stripe), Connect vklopljen kot marketplace. Ključi na Renderju: `STRIPE_SECRET_KEY`
  (`sk_test_…`), `STRIPE_WEBHOOK_SECRET` (`whsec_…`) — nastavi Martin. Brez webhook skrivnosti Stripe nakupi vrnejo 503.
- Webhook endpoint `https://outly-backend-roy3.onrender.com/stripe/webhook`, dogodki: `checkout.session.completed`,
  `checkout.session.expired`, `checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`,
  `charge.refunded`, `account.updated`. Če je `account.updated` za povezane račune na ločenem endpointu: `STRIPE_CONNECT_WEBHOOK_SECRET`.
- Poti: `POST /business/stripe/onboard` (lastnik → `{url}` Stripovega obrazca), `GET /business/stripe/status` (lastnik/manager),
  `POST /business/stripe/dashboard` (lastnik → Express pregled). Nakup v Stripe načinu vrne `mode:"stripe"`, `checkout_url`, `tickets: []`.
- **Odjemalci še ne znajo `checkout_url`:** iOS in splet morata ob `mode:"stripe"` odpreti `checkout_url` (iOS: Safari/SFSafariViewController,
  brez paketa), nato osvežiti `GET /me/orders`. Do takrat Stripe nakup deluje samo za klube z dokončanim onboardingom; ostali v sandboxu kupujejo testno.
- **Vračil prek API-ja ni** (poti ni): vračilo se naredi v Stripovi nadzorni plošči, webhook `charge.refunded` ga zapiše (`refunded_cents`, stanje, vstopnice).
- **Potrdila po e-pošti ni** (pravna analiza 1. 10., točka 3): do takrat samo Stripov račun, če je v nadzorni plošči vklopljen (Settings → Emails → Successful payments).
- **Past:** plačilo za že preklicano naročilo (seja potekla, nato vseeno plačana — redko) se NE vknjiži samodejno: dnevnik izpiše
  `POZOR: placilo za neaktivno narocilo …`, vrni ga ročno v Stripu.
- Klic Stripa (ustvarjanje seje, ~0,5–1,5 s) teče znotraj nakupnega mesta (`NAKUP_VZPOREDNO`, I16) — pod navalom manjša prepustnost.
- **Stripe politika »Accounts v1 support« je vklopljena v sandboxu** (3. 10., Martin): Stripe sicer zavrne `accounts.create` (Express v1).
  Pred live jo vklopi tudi v živem računu ali preklopi na Accounts v2 (`/v2/core/accounts`). Ustvarjanje računa kluba je brez
  Stripovega idempotentnega ključa (zapomni si tudi zavrnitev 24 h), hkratne klike serializira `pg_advisory_xact_lock` na klub.
- Pospravljalec vsakih 5 min (`STRIPE_POSPRAVI_MS`) preveri `pending` naročila s preteklim rokom pri Stripu (zaključi, preklice ali vknjiži).

## Nakup brez računa (od 5. 10. 2026; ARCHITECTURE »Nakup brez računa«, I22, DECISIONS 5. 10.)

- **Odjemalec (web-dev):** `POST /guest/events/:id/orders`, `GET /guest/order`, `POST /guest/order/cancel` (glava `X-Guest-Token`; povezave imajo žeton v `#t=`). **iOS ni** (Martin). **Stikalo `GOST_NAKUP_LIVE=1`** za pravi denar (Martin). Po vrnitvi s Stripa je naročilo lahko še `pending`: stran naj poizveduje, dokler ni `paid`.
  **Past:** če je kupec prijavljen z istim e-naslovom, `GET /me` (zagon aplikacije) naročilo prevzame in PRESEKA žeton: `GET /guest/order` da 404 — stran naj ob 404 s sejo odpre My tickets.
- **Past:** gost, ki izgubi stran med plačilom, ne dobi `checkout_url` nazaj (409 »unfinished payment« do ~35 min) razen s ponovitvijo z istim `Idempotency-Key`; mail pride šele po plačilu.
- **Past:** v vseh poslovnih pogledih je gost »Guest« (`is_guest`), lastnik/manager vidita `buyer_email` kot pri vseh; vratar ga ne vidi nikjer, tudi ne v `POST /business/tickets/scan` (8. 10. 2026: `buyer_email`/`holder_email` se pri vlogi `doorman` zbrišeta na vrstici pred vsemi vejami odgovora; nova veja skena z `ticket: t` je pokrita sama; iOS `ScanTicketInfo` in splet `posel-skener.js` e-naslovov ne berejo).
- **Meja:** mail z vstopnico gre na katerikoli naslov, ki ga vpiše kupec (v testnem načinu brez plačila): največ 10 nakupov/h/IP in 1 mail na naslov/24 h; `reply_to` luka@outly.si. Mail ni popoln: firma/matična kluba ni v bazi (ZVPot-1 7/1, 130/1) — odločitev Martina/pravnika.
- **Predpostavke:** žeton do konca dogodka + 30 dni; e-naslov plačanega naročila 180 dni po dogodku (`GOST_HRAMBA_DNI`); neplačanega 24 h. V varnostnih kopijah (30 dni) e-naslovi ostanejo; po obnovi se anonimizacija ponovi sama.

## Prenos vstopnice prijatelju brez računa (od 5. 10. 2026; ARCHITECTURE »Prenos vstopnice prijatelju brez računa«, I23, DECISIONS 5. 10.)

- **Odjemalca (ios-dev, web-dev):** `POST /tickets/:id/transfer` dobi `allow_guest`, `age_confirmed`; `GET /me` (in `PATCH /me`) `can_transfer_to_guest`; nova `GET /guest/ticket` (glava `X-Guest-Token`, splet `/app/guest/ticket#t=`). Poslovni pogledi: `is_guest_holder`, imetnik `Guest`. Podrobnosti API-ja v ARCHITECTURE.
  **Stikalo `PRENOS_BREZ_RACUNA=vsi`** vklopi Martin po objavi pogojev 1.2 in politike 2.5; do takrat samo vloga `admin`.
- **Past:** ob uspešnem prenosu gostu je pošiljateljeva vstopnica POSLANA; če mail ne gre (napačen naslov, 8 poskusov ~42 h izčrpanih), vstopnice ne dobi nihče (v dnevniku `[gost] POZOR: mail s prenesene vstopnice …`, brez e-naslova). Razveljavitve ni.
- **Past:** Resend (SDK 3.5) sledenja odpiranju/klikom ne izklaplja na mailu, ampak na domeni (Resend → Domains); pravna presoja zahteva brez sledenja, zato to nastavitev preveri Luka/Martin. Inline slika (`content_id`) in priloga PDF sta preverjeni samo proti lažnemu strežniku.
- **Past:** PDF vstopnice uporablja osnovno pisavo (Helvetica, WinAnsi): č, ć, đ se v PDF izpišejo kot c, c, d (š, ž ostanejo); koda QR je enaka.
- **Postopek: ugovor/izbris prejemnika** (odgovor na mail ali zahteva): admin (račun z vlogo admin) pokliče `POST /admin/api/guest-tickets/erase` z `{ "email": "<naslov>" }`; odgovor `{ tickets, transfers }`. Povezava preneha delovati, vstopnica in koda v mailu veljata naprej (vrnitev pošiljatelju ročno). Ni v admin panelu.
- **Meja (GDPR 21, za Martina/pravnika):** po izbrisu (erase ali anonimizacija) se štetje na naslov pozabi in seznama zavrnjenih naslovov ni: pošiljatelj lahko isti naslov spet vpiše.
- **Meja:** po prevzemu v račun se serial NE zamenja (PDF/koda v mailu veljata naprej); ugovor prejemnika (21(4)) gre z odgovorom na mail (ročno), gumba »Zavrni vstopnico« ni.

## Guest lista (od 8. 10. 2026; ARCHITECTURE »Guest lista«, I24, DECISIONS 8. 10.)

- **Odjemalca (ios-dev, web-dev):** nove poti `GET /me/guest-lists` (404 na starem backendu: razdelek skrij), `POST /me/guest-lists/:id/invites { user_ids, age_confirmed? }`, `DELETE /me/guest-lists/:id/invites/:userId`; nova polja `is_guest_list` (privzeto false) in `guest_list_host_username` (privzeto null) v `GET /me/tickets`, odgovoru skena,
  `scan-list` in poslovnih vstopnicah; `transferable` je pri guest listi false, prenos 409 `Guest list tickets can't be transferred.`. Napake: besedilo (403/409, `userMessage`) in JSON 400 `age_confirmation_required` + `min_age` (kot prenos). **Dodatno k pogodbi:** 409 `This guest list has reached its limit of changes. Contact Outly.` (meja 60 vrstic povabljencev na listi, tudi odstranjenih).
  Povabljenec dobi vstopnico (obvestilo: spodaj, migracija 036; NI v `/me/tickets/received`); razveljavljene (`void`) vstopnice guest liste `GET /me/tickets` ne vrača; `GET /me/orders` guest liste ne vrača (ni nakup). VIP razdelitev po nakupu (točka 1 pogodbe) je samo odjemalca: backend nespremenjen. Admin panel (zavihek »Guest lists«) je že v `admin/index.html`.
- **Obvestilo o vabilu (8. 10., migracija 036; ARCHITECTURE »Guest lista«, DECISIONS 8. 10.):** **Odjemalca (ios-dev, web-dev):** `GET /me` novo polje `pending_guest_list_invites` (int, privzeto 0), nova `GET /me/guest-list-invites/received` → `{ invites: [{ id, guest_list_id, ticket_id, host_username, host_avatar_url, created_at, event: { id, title, start_at, poster_url, club_name } }] }` (404 na starem backendu: brez vrstic, brez napake) in `POST /me/guest-list-invites/received/:id/seen` → `{ ok: true }` (pozor: za razliko od `/me/tickets/received/:id/seen`, ki vrača `{ result: "ok" }`).
  Zvonec: značka = `pending_received_tickets + pending_club_events + pending_guest_list_invites`; vrstica »@host added you to their guest list« + dogodek · klub · datum; dotik: `seen`, nato odpri vstopnico (`ticket_id`). Nizi: `%@ added you to their guest list` / sl `%@ te je dodal na svojo guest listo`. Brez maila in pusha (Martin 8. 10.; push ne obstaja).
  **Past:** števec in seznam delita pogoje (`GUEST_LISTA_NEPREBRANA_IZ/_KJE` v `index.js`); novega pogoja ne dodajaj samo v enega (značka brez vrstice).
- **Past (vsak, ki piše poizvedbo po `orders`/`tickets`):** narocilo guest liste JE vrstica `orders` (total 0, `paid`): vsaka nova agregacija PRODAJE mora imeti `o.guest_list_id IS NULL`, sicer guest lista napihne število naročil, kupcev in vstopnic. Test I24 ujame samo obstoječe poti.
- **Past:** `checked_in` (prodajni pregled, finance) šteje tudi vstope z guest liste, zato je lahko večji od `tickets_sold`. Dogodek z guest listo se ne da izbrisati (`DELETE /events/:id` ga odpove, FK); lastnik kluba, katerega dogodek ima guest listo, računa ne more izbrisati (`club_has_orders` šteje tudi naročila liste).
- **Predpostavke agenta (Martin jih ni potrdil):** guest lista ne šteje v kapaciteto (skupaj s prodajo lahko preseže `capacity`); lista samo za objavljen dogodek; ena aktivna lista na (dogodek, gostitelj). Postavljeno z migracijo 035 (samo dodajanje); PR je pod `odobril-martin` (migracija + `orders`/`tickets`).

## Organizatorji brez prizorišča (od 9. 10. 2026; ARCHITECTURE »Organizatorji brez prizorišča«, I26, DECISIONS 9. 10.)

Za **ios-dev** in **web-dev** (backend po migraciji 037; vse polja so DODANA, stari odjemalci jih spregledajo; v modelih privzete vrednosti, ker stari backend polj nima):
- Klub: `is_organizer`, `is_official` (bool, privzeto false) v `GET /clubs`, `/clubs/:id`, `/business/clubs/me`, `/me/clubs/following`; `GET /me` `clubs[]` ima `is_organizer`. Vhod: `isOrganizer` v `POST /clubs` in `PATCH /business/clubs/me` (mesto neobvezno); `is_official` ni vhod.
- Dogodek (vsi odgovori z dogodkom + `/me/tickets`, `/guest/order`, `/search`): `venue_club_id`, `venue_club_name`, `venue_club_logo_url` (null brez gostitelja), `venue_name`, `venue_address`, `venue_city` (prazen niz), `venue_lat`, `venue_lng` (null). »Kje je dogodek« = `venue_club_name` ?? (`venue_name` neprazno ? venue_* : naslov kluba). V pogledih vstopnic (`/me/tickets`, `/guest/order`, `/guest/ticket`) sta `address` in `city` že prizorišče (gostitelj ali venue_*), ne organizatorjev naslov.
  `GET /events` ima novo `club_name` (organizator). **`GET /events?clubId=X` vrne tudi gostovane dogodke z `hosted: true`** (lastni `hosted: false`); brez `clubId` `hosted` ni. Poti `GET /clubs/:id/events` NI.
- Vhod dogodka (`POST /events`, `PATCH /events/:id`): `venueClubId` ali `venueName`+`venueCity` (+`venueAddress`, `venueLat`+`venueLng`); organizator brez prizorišča = 400 »Organizer events need a venue.«; lastni klub 400, neobstoječ/skrit gostitelj 404. Urejevalnik naj pošlje celo prizorišče (gostitelj ali prosto); `venueClubId: null` izbriše gostitelja.
- **Stari backend (pred 037)**: polj ni, `?clubId=` brez `hosted`, `isOrganizer` se prezre; odjemalec ne sme pasti (privzete vrednosti). Razdelek »Organized by Outly«: `GET /clubs` (`is_official`) + `GET /events?clubId=&upcoming=true` (strežnik nima posebne poti).
- Past: `is_official` nastavi samo admin (`/admin/api/clubs`); prvi uradni profil mora Martin/admin ustvariti ročno (lastnik = račun Outly), brez njega razdelka ni.

## Predpostavke agenta (še veljajo; Martin jih ni izrecno potrdil)

- **Stripe v sandboxu (3. 10.):** klub brez dokončanega Connect onboardinga v sandboxu še vedno prodaja v testnem načinu (da demo klubi
  in TestFlight ne obstanejo). Z `sk_live_` takega nakupa ni (409). Povratni naslovi Checkouta in onboardinga vodijo na `outly.si/app`
  (`/app/tickets`, `/app/event/:id`, `/app/business/:klub/settings?stripe=vrnitev|osvezi`) — splet jih še ne obravnava posebej.

- **Prijatelji (20. 9., backend #45; čaka Martina v #47):** (1) iskanje po uporabniškem imenu (`GET /users/search`, predpona,
  samo potrjeni, največ 10, 120/h); (2) `users.share_plans_with_friends` privzeto VKLOPLJENO; (3) »Invite more« deli
  `https://outly.si` brez `?ref=` (točke živijo v Supabase). Drugačna odločitev = tri majhne spremembe + popravek politike.
- **Več ekip na osebo (018):** brez glave `X-Outly-Club` poslovni klici dobijo **prvo (najstarejše) članstvo** — dve ekipi in
  manjkajoča glava = tiho urejanje napačnega kluba. iOS nastavi `APIClient.currentClubId` ob vstopu v klub in ga ob izhodu pobriše.
  `DELETE /business/team/me` brez glave zapusti VSE ekipe.
- **Pogoji/politika (outly_webpage):** sprememba pogojev = dvigni `TERMS_VERSION` v `auth.js` (zdaj 1.1); registracija v iOS
  aplikaciji `terms_version` ne zapiše. Nova funkcija, ki zbira ali kaže osebne podatke, = popravek politike zasebnosti.
- **iOS »My preferences« in filtri domačega zaslona so samo na napravi** (@AppStorage); backend jih ne pozna. Strežniško = nova
  pot/stolpec na `/me` (samo dodajanje). Histogram razdalje je brez dovoljenja za lokacijo prazen — ni hrošč.
- **`event_favorites`**: pot v backendu ostane, iOS je od outly-app #23 ne kliče več — kandidat za odstranitev (API samo dodajanje).

## Znane pasti (aktivne)

- **Omejevalnik poskusov je v bazi (`omejitve`, #24, I15) in šteje po IP** (IPv6 po /64; prošnji ustvarjalca in prijateljev imata od #110 ločena ključa): meje preživijo deploy, blokada traja do konca okna (največ 1 h);
  sprostitev = oštevilčena migracija `TRUNCATE omejitve` + restart servisa (proces si blokado zapomni do konca okna). CGNAT ali skupni Wi-Fi kluba lahko zadene 20 nakupov/h na IP.
- **Izvoz baze je tok; ne vračaj ga v `res.json`** (#23; ARCHITECTURE »Varnostne kopije«). Panel odgovor še prebere v celoti (`res.json()`): pri zelo velikih bazah prenos shrani neposredno.
- **Migracija brez zaklepa pade, deploy pade, stara različica ostane živa** (#115, `db/migrate.js`, test `test_migracija_zaklep.js`): vsaka
  migracija teče v transakciji z `lock_timeout` 2 s (kratko: čakajoči ALTER blokira nove poizvedbe, tudi sken), `statement_timeout` 120 s (na stavek) in 4
  ponovnimi poskusi po 10 s ob zaklepu; advisory lock čaka največ 60 s (env `MIGRACIJA_*`, `.env.example`). Nato izhod 1: `npm start` se ne zažene, Render obdrži
  staro različico, v `schema_migrations` ni vnosa → poskus znova ob naslednjem deployu. **Stara različica vrača 200, zato `Nadzor`
  tega ne vidi** (alarma za to ni): po merge-u preveri `list_deploys` (zadnji deploy za commit = live) ali da `/healthz` vrne `commit`
  z `main` (prvih 12 znakov). Ukrep: poišči dolgo transakcijo (`pg_stat_activity`), počakaj, ponovno sproži deploy. Migracija
  ne sme sama klicati `COMMIT`/`SET lock_timeout`.
- **Vsak `pool.connect()` z dolgo transakcijo** rabi `c.on("error")`, odklop počasnega bralca in `idle_in_transaction_session_timeout` (kot izvoz); mirujoče povezave ujame `pool.on("error")` (#106, `test_pool_napaka.js`).
- **Express 4 ne ujame zavrnjene obljube ročnika** (#129): neujet `await` (npr. `pool.connect()` pred `try`) je sesul cel proces. Varuje `asinhroni_rocniki.js` (503/500, I10); nov `Router`/`app` ga podeduje, ne dodajaj `process.on("unhandledRejection")`.
- **Vloga `backup` (#116, migracija 029) sme SAMO `GET /admin/api/export`**: `requireAuthNa` jo povsod drugje zavrne (403), `neobveznaPrijava` jo šteje za neprijavljeno, izvoz je na `app` (ne na routerju `admin`).
  Drugim je skrita (`/users/search`, prošnje za prijateljstvo → 404 `no_account`). **Izvoz: največ 1 hkraten na proces** (drugi dobi 429 + `Retry-After: 30`, `izvoz.sh` ponovi); števec sprosti `finally` ali zgodnji izhod, če je odjemalec že odšel (`res.destroyed`; past: `close` je že oddan, ne čakaj nanj). Nova pot je zanjo varna brez dela.
  Račun za kopije je do Martinovega preklopa (skill `obnova-baze`) še `agent@outly.si`. Vrstica `users` nastane ob prvem klicu z žetonom z `user_metadata.email_verified=true` (sicer 403 »Email not verified.« brez vrstice); šele nato admin nastavi `backup`.
- **Obnova izvoza zahteva POPOLNOMA prazno ciljno bazo**, migracija 007 pa vstavi `agent@outly.si` → pred obnovo na cilju
  `DELETE FROM users;` (ARCHITECTURE, postopek obnove). Past odpade, ko servisni račun ne bo več v migracijah.
- **iOS `OutlyAsyncImage`** (29. 9., outly-app #33) pomanjša na 1200 px in predpomni po URL-ju: slika z novo vsebino na istem URL-ju bi
  ostala stara. Cloudinary da vsakemu nalaganju nov `public_id`; če se to spremeni, dodaj URL-ju različico.
- **iOS, izrisovanje** (29. 9., #31/#32): vrednosti po frameu v majhen `ObservableObject`, ki ga opazuje samo podpogled (`DrsenjeHome` ->
  `HomeOzadje`) ali referenco brez opazovanja (`IzvoriRazkritja`). `MainTabView` ne sme opazovati `SessionStore`; `refreshMe`
  objavi `me` samo ob spremembi (`Me: Equatable`). `DateFormatter` ne ustvarjaj v računani lastnosti — `DateParsing.oblikovalnik("…")`.
- **iOS prehod Home -> Search/Profile** (29. 9.; #34–#38, vrnjeno z #39): posnetek zaslona vsebuje zamegljeno ozadje (raste »kartica«),
  izločanje ozadja (#38) je na napravi odstranilo vso vsebino. Deluje: živa vsebina raste s `scaleEffect` (`VstopZavihka`),
  `prosojnost: 1`, oster posnetek Home pojema nad vsem (`ZabrisSloj`). Brez posnetka zaslona animacij ne spreminjaj.
- **iOS:** nov zaslon v zavihkih Search/Profile (tudi potisnjen) rabi `.outlyOzadje()`, ne `.background(Color.black…)`.
  `.refreshable` vedno `await Task { await load() }.value` (sicer »Connection problem«). Nova datoteka z `ObservableObject` rabi
  `import Combine`. Ključ v `Localizable.xcstrings` ne sme trčiti z drugim po veliki/mali črki ali ločilih (Xcode 26 generira
  simbole; `STRING_CATALOG_GENERATE_SYMBOLS = NO` to izklopi — preveri, da ostane).
- **macOS minute** se štejejo ×10: iOS gradnja z uploadom ~8–10 min = 80–100 od 2000 brezplačnih minut/mesec; PR ~4 min.
- **TestFlight certifikat** »Outly CI« (`IOS_DEV_CERT_P12` + geslo v secrets) velja do ~20. 9. 2027; preklic/potek = korak
  »Podpisan arhiv« pade, PR-ji ostanejo zeleni. Postopek v outly-app `CLAUDE.md`.
- **Oznaka »skip ci« na backend PR-ju blokira merge** (`Testi` se preskoči, `Zascita` teče, PR ostane »Expected — waiting«).
  GitHub jo išče v **celem** sporočilu commita, zato jo v sporočilih omenjaj samo opisno, brez oglatih oklepajev.
- **GitHub »Budgets and alerts«**: Actions 20 $/mesec s »Stop usage: Yes« (privzeto 0 $ — ob porabljeni kvoti bi stalo vse, tudi
  `Testi` in `Nadzor`). Šteje se po obračunskem ciklu (1. v mesecu). Codespaces, Packages, Git LFS, AI Credit namerno 0 $.
- **GitHub cron `*/15` teče na 4–5 ur, ne na 15 min** (17.–18. 9.: sedem zagonov v 24 h). Izpad je lahko neviden do 5 ur, zato je
  hiter alarm UptimeRobot (ARCHITECTURE, Nadzor), Healthchecks ima Period 6 h / Grace 3 h. »Vsakih 15 min« opisuje cron.
- **Agent na GitHubu JE lastnik.** Vsa dejanja iz sej Claude Code gredo prek računa `Djurdje` (API `get_me` 18. 9. 2026),
  ki je edini sodelavec repa z vlogo `admin`. Zato so oznaka `odobril-martin`, ruleset za `main` in »agent si oznake ne sme
  dodati sam« **dogovor, ne varovalo**: isti račun lahko oznako doda, ruleset izklopi ali potisne mimo. Trdo postane šele,
  ko seje tečejo prek ločenega računa z vlogo `write` (brez admin) in je ruleset brez izjem za bypass — glej #15.
- **`Zascita`** je obvezna tu (#15) in dodana v `outly_webpage` (#23) in `outly-app` (#44); v `outly-app` (zasebni repo, brezplačni
  GitHub) ne more biti obvezna.
- **`jq` in `^`**: v `jq` je `^` zasidran na cel niz, ne na vrstico — vzorec čez vrstice diffa rabi `(?m)`.
  Brez tega filter tiho ne ujame ničesar in preverba je videti zelena. (Ujeto pri pisanju `zascita.yml`.)
- **Oblačne seje nimajo izhoda** do `onrender.com`, `outly.si`, `*.pages.dev`, `supabase.co`, `ntfy.sh`, `download.swift.org` in
  GitHub *releases* (403 prek agent proxyja). iOS prevod preveri `Gradnja iOS` na PR-ju (+ `type-checker`); backend ročni zagon
  **`Nadzor produkcije`** (`workflow_dispatch` na `main`, `test=false`, korak »Preveri produkcijo« izpiše `OK <ime> (<status>)`).
  Zelen Nadzor ne dokaže, da teče nova koda (Render ob neuspelem deployu pusti staro) — ob dvomu preveri novo polje v odgovoru.
- **Headless preverjanje outly.si:** stubati je treba samo Supabase (`*.supabase.co`; supabase-js in Inter sta v `vendor/`,
  `assets/fonts/`). Playwright: `npm i playwright` v scratchpadu + `executablePath` `/opt/pw-browsers/chromium-*/chrome-linux/chrome`.
- `owner_user_id` ni več v javnih odgovorih klubov (#113, I4; arhiv `STATE-do-2026-10-02c.md`). **ios-dev** (neurgentno): odstrani `APIClub.ownerUserId`.
- **Idempotentni ključ nakupa (#112, I18).** Glava `Idempotency-Key: <UUID>` na obeh `POST …/orders` (brez nje vse kot prej): en UUID na pritisk »Kupi«, isti ob
  ponovitvi ISTEGA nakupa, nov ob spremembi nakupa. Ponovitev = 201 + `Idempotent-Replayed: true` s TRENUTNIM stanjem; neaktivno 409, drug nakup 422. iOS (#53) in splet (#29) ga pošiljata.
- **Prenesena vstopnica v kupčevem pogledu naročil (#124, I7; od 2. 10. 2026):** `serial` je `null` (ključ ostane), `holder_email` ni (`GET /me/orders`, odgovor nakupa in ponovitev); nadomestilo
  `holder_username` + `transferred`. Prejemnik (`GET /me/tickets`) in klub (poslovne poti) serial še imata. iOS: `serial` opcijski (outly-app #54); splet `/me/orders` ne kliče. **Isto za odgovor `POST /tickets/:id/transfer` (#140, od 2. 10. 2026):** pri prenosu po `user_id` je `ticket.holder_email` `null` (ključ ostane; pri prenosu po e-naslovu je vpisani naslov); odjemalci polja ne berejo (grep iOS `Outly/`, splet `webapp/`: 2. 10.).
- Ostale pasti (AsyncImage brez okvirja, gnezden NavigationStack, pg BIGINT, Resend `{error}`, JSONB vs ARRAY)
  so v `CLAUDE.md` tega repa in iOS repa.

## Kar nobeno orodje ne ve

- **Video s telefona:** Martin naloži posnetek na Drive `bozicmartin7@gmail.com`, nastavi »Anyone with the link«; agent prenese s
  `curl "https://drive.usercontent.google.com/download?id=<ID>&export=download&confirm=t"` (domeni dovoljeni v omrežju okolja;
  Drive konektor sam vrne le ~100 KB). ffmpeg: `pip download imageio-ffmpeg`. iOS sliko zapiše samo ob spremembi zaslona — luknje
  v `pts_time` so zastoji. Po analizi video pobriši in Martina spomni, naj povezavo vrne na »Restricted«.
- **Slike klubov v produkciji so ZA DEMO** (vzete s spletnih strani klubov). Pred pravim zagonom jih morajo
  zamenjati slike, ki jih dajo klubi sami — z dovoljenjem. Tega ne pove noben test.
- **Demo podatki:** 5 klubov z izmišljenimi imeni (Velvet, Nexus, Mirage, Mansion, Olie; migracija 022), lažni telefoni
  `+386 1 620 41 x0` in `@example.com`, izmišljeni naslovi v centru LJ. Logotipi lastni (023, `outly_webpage/assets/clubs/` —
  **najprej objava slik, nato migracija**). Velvet ima tri dogodke s Martinovimi plakati (024: 12. 10. 2026, 26. 4. 2027, 21. 6. 2027;
  na plakatih piše »sobota«, datumi so ponedeljki). **Galerije in ostali plakati so še slike pravih klubov** — zamenjati prek »Edit
  your page«. Računi: kupec `gost@outly.si`, admin `martin…`, servisni `agent@outly.si`.
- **»Dela« pomeni: zelen Actions IN Martin preveril na napravi.** Dokler drugega ni, se piše
  »preverjeno s parse + pregledom tipov, na napravi ne«. Kaj čaka na napravo, je v #18.

## Način dela

- **Varčevanje z macOS minutami** (od 21. 9., dokler ni Xcode Cloud): en merge v `master` na delovni dan oz. zaključen sklop; push na
  PR vejo šele po `type-checker`; vmesni iOS pushi z oznako »skip ci«, zadnji brez. Na backendu te oznake ne uporabljaj (Linux, ×1).
  Ne zbiraj več kot en dan ali nepovezanih stvari v en PR. 29. 9. je bilo 5 merge-ov (Martin je sproti preverjal) — ob ponovitvi
  vprašaj Martina, ali naj se vmesni koraki zbirajo na veji.
- **Luka ima MacBook z Xcodom** (od 20. 9.): lokalna gradnja je dodatna preverba, ne nadomestilo za veja + PR + zelen Actions.
