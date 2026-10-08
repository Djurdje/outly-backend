# Odločitve — Outly (vsi trije repozitoriji)

Edini vir odločitev za backend, iOS aplikacijo in spletno stran. Vsaka vrstica: datum, odločitev, razlog.
Odločitve se ne odpirajo znova brez Martina. Nova odločitev = nova vrstica na koncu razdelka, stara se ne briše.

## Format pomembne odločitve

Vsaka **pomembna** odločitev (taka, ki nekaj stane, veže na ponudnika ali jo bo kdo čez pol leta hotel razumeti)
dobi poleg datuma, odločitve in razloga še tri polja. Manjše odločitve ostanejo ena vrstica.

- **vir/dokaz** — od kod vemo, da je to prav: meritev, številka, člen zakona, sestanek, stran ponudnika.
  Brez tega je odločitev mnenje in jo bo nekdo čez mesec dni po nesreči odprl znova.
- **velja dokler** — pogoj, ob katerem odločitev sama od sebe zapade in jo je treba pogledati znova
  (npr. »dokler je ena instanca backenda«, »dokler je račun Individual«). Če pogoja ni videti, napiši »trajno«.
- **nadomeščena z** — kdaj in s čim je bila odločitev preklicana. Stara vrstica ostane, samo dobi to polje;
  nič se ne briše, da je zgodovina berljiva.

Primer oblike (izmišljena odločitev, samo da se vidi postavitev):

> 2026-09-20: **Cache javnih poti 60 s.** Razlog: `/events` je 70 % vseh klicev.
> *vir/dokaz*: Render metrike 19. 9., 4.100 klicev/uro · *velja dokler*: teče ena instanca backenda · *nadomeščena z*: —

## Poslovni model in pravo

- 2026-09: **Denarnice v aplikaciji NE BO.** Denar se v aplikaciji ne hrani. Razlog: hramba sredstev = izdajanje
  elektronskega denarja (ZPlaSSIED, dovoljenje Banke Slovenije). Zasloni Add money / Withdraw / Balance iz Figme se ne gradijo.
- 2026-09: **Prodajalec vstopnice je KLUB, Outly je posrednik** s provizijo. V promet NEXT DIMENSIONS šteje samo
  provizija; DDV in vračila so obveznost kluba. Tehnično: Stripe Connect, destination charges, `application_fee`.
  *velja dokler*: Outly sam ne postane prodajalec (takrat DDV, blagajna in vračila preidejo na NEXT DIMENSIONS).
- 2026-09-08: **Provizija Outlyja je 10 %** (`PROVIZIJA_ODSTOTEK`, privzeto 10).
  *velja dokler*: ne podpišemo drugačne pogodbe s klubi; odstotek je spremenljivka okolja, ne koda.
- 2026-10-03: **Provizija po klubu** (Martin: »z vsakim klubom drugačna provizija, nekje 5 %, nekje 2 %«). `clubs.commission_bps`
  (bazne točke, migracija 031) nastavi samo admin v admin panelu; prazno = privzeta 10 %. Zamrzne se na naročilu ob nakupu.
  Lastnik jo vidi v `GET /business/sales` (`fee_percent`), spremeniti je ne more. **Odprto (Martin):** Stripovo provizijo
  (~1,5 % + 0,25 €) pri destination charge plača Outly iz svoje provizije – pri 2 % in vstopnici 15 € je to izguba; možnosti:
  strošek prenesti na klub, servisni strošek kupcu ali spodnja meja provizije. *vir/dokaz*: pogovor 3. 10. 2026,
  `_testi/test_stripe.js` (»nakup 15 EUR pri 2,5 %: provizija 38 c«) · *velja dokler*: drugače ne odloči Martin · *nadomeščena z*: —
- 2026-09: **Kartica se nikoli ne vnaša v naš vmesnik** (PCI DSS SAQ D). Uporabi se Stripov gostovani obrazec.
- 2026-09-14: **Stripe Checkout (gostovana stran) namesto Stripe SDK** — razlog: brez Xcoda ne moremo dodati
  paketa v iOS projekt; Apple Pay pride s Checkoutom sam.
  *velja dokler*: nimamo Maca/Xcoda za dodajanje paketov v iOS projekt.
- 2026-09: **Zneski v evrih, v centih kot celo število.** Figma ima $, mora biti €.
- 2026-09: **Meja starosti 15 let** (ZVOP-2, 8. člen — v Sloveniji 15, ne 16). Preverjata aplikacija in strežnik.
  Dogodek 18+ zahteva datum rojstva in starost ≥ `min_age` (invarianta I8 v ARCHITECTURE.md).
  *velja dokler*: velja ZVOP-2 v tej obliki in delujemo samo v Sloveniji.
- 2026-09: Pri vstopnici za dogodek na določen datum **ni pravice do odstopa v 14 dneh** (ZVPot-1 135/12) — piše v nakupu.
- 2026-09-11: Pravni dokumenti: `outly.si/terms` in `outly.si/privacy-app` (slovenska, aplikacija + waitlist),
  `outly.si/privacy` (angleška, spletna stran). Rok vračila ob prestavitvi dogodka 14 dni, obvestilo o spremembi 15 dni.
- Upravljavec podatkov: NEXT DIMENSIONS, družba za marketing, d.o.o., Trebče 81, 3256 Bistrica ob Sotli (matična 7238274000).
  Kontakt projekta luka@outly.si.

## Identiteta in računi

- 2026-09-10/11: **Supabase Auth je edina identiteta** za spletno stran IN aplikacijo (projekt `zbewqcxnvrwebxonvebx`).
  Backend preverja Supabasov JWT prek JWKS; lastni `/auth/*`, refresh žetoni in `password_hash` so odstranjeni (migraciji 010, 011).
  *velja dokler*: sta spletna stran in aplikacija en sam Supabase projekt; izpad Supabase je izpad prijave (invarianta I10: 503, ne odjava).
- 2026-09-11: `users.id` ostane INTEGER, doda se `users.supabase_uid` UUID (obstoječi računi/klubi/vstopnice ostanejo).
- 2026-09-11: iOS uporablja **tanek REST odjemalec za GoTrue** (`SupabaseAuth.swift`), ne supabase-swift (brez Xcoda ni paketov).
  *velja dokler*: nimamo Maca/Xcoda za dodajanje paketov (isti pogoj kot Stripe Checkout).
- 2026-09: **En program za uporabnike in klube.** Vloge `user | business | admin` uveljavlja strežnik; aplikacija kaže drug obraz.
- 2026-09-11: Ekipa kluba: lastnik (`clubs.owner_user_id`) + člani `manager | doorman` (`club_members`); ~~uporabnik je v največ
  eni ekipi~~; vratar sme samo skenirati in gledati vstopnice dogodka. Član nastane šele ob sprejemu vabila (`club_invites`, 013).
- 2026-09-21: **Ena oseba je lahko v ekipi več klubov** (Luka; nadomešča »največ ena ekipa« iz 11. 9.): vratar iz K4 dobi in
  sprejme vabilo tudi iz Cirkusa; vloga velja po klubu. Migracija 018 (`UNIQUE (club_id, user_id)` namesto `UNIQUE (user_id)`).
  Kateri klub aplikacija misli, pove z glavo **`X-Outly-Club: <id>`** (ali `?club_id=`); brez nje backend vzame prvo (najstarejše)
  članstvo — star odjemalec dela naprej. `GET /me` dobi seznam `clubs` (id, ime, logo, vloga); `club_id`/`club_role` ostaneta.
  Lastnik kluba še vedno ne more biti član druge ekipe (ima klubski profil). Sprejem vabila drugih vabil več ne zavrne.
  *vir/dokaz*: Lukovo naročilo 21. 9. (»mora biti tako, da lahko povabiš isto osebo v več klubov«). *velja dokler*: — *nadomeščena z*: —
- 2026-09: **En klub na poslovni račun** (lastnik ima en klub). *velja dokler*: nihče od strank ne vodi dveh lokalov
  (`klubUporabnika()` vzame prvi klub — veriga lokalov to odločitev odpre). Ne meša se z zaposlenimi: ti so od 21. 9. lahko v več ekipah.
- 2026-09-08: **Admin panel je spletna stran v `outly-backend/admin/`**, preprosta, v slogu konzole, brez Figme. Prvi admin je Martin.
- 2026-09-08: Servisni admin račun `agent@outly.si` za agentova dejanja v produkciji (geslo ima Martin; nikoli v datotekah).
  *velja dokler*: agent res potrebuje admin pravice v produkciji — ko jih ne, se račun degradira (naloga v Issues).

## Produkti in vsebina

- 2026-09-09/10: **Povabilo prijateljev**: brez nagrad; 1 točka na vabilo, šteje šele ob potrditvi maila povabljenega;
  invite link samo za registrirane uporabnike (nadomešča odločitev z 9. 9., ko je bil link tudi na confirm.html).
  *nadomeščena z*: 2026-09-20 (del »brez nagrad«); štetje točk in pogoj potrditve maila ostaneta.
- 2026-09-20: **Točke bodo unovčljive v aplikaciji** — spletna stran (razdelek »Earn points before launch«, outly_webpage PR #5)
  obljublja: popusti na vstopnice, Outly »kariera« (status), ekskluzivni dostop do dogodkov, »več prihaja«. Zbirajo se zdaj
  (waitlist, `referred_by` + potrjen mail), unovčijo po zagonu aplikacije. *vir/dokaz*: Martinova predloga plakata in
  naročilo 20. 9. *velja dokler*: mehanizem unovčenja ni določen — backend točk še ne pozna (živijo v Supabase `waitlist_signups`);
  kaj točno stane popust/status, koliko točk, je odprta naloga (Martin).
- 2026-09-10: Registrirani se v javni waitlisti kažejo z delno zakritim imenom + »created a profile«.
- 2026-09-10: Zavihek Saved umaknjen; **Liked events** je razdelek na domačem zaslonu (nav bar: Home, Search, Map, Profile).
- 2026-09-14: Gumb **Bar prices** na zaslonu dogodka odpre cenik, ki ga klub sam ureja v aplikaciji (`clubs.bar_prices` JSONB, 014).
- 2026-09-20: **Prijatelji v aplikaciji** (Martin): »My friends« v profilu (pod My Clubs), prošnje za prijateljstvo v obvestilih,
  razdelek **»Your friends' plans«** na domačem zaslonu (pod In your area: avatarji prijateljev, »Invite more«, »View«) in prenos
  vstopnice **prijatelju iz seznama** namesto vpisa e-naslova (e-naslov ostane kot druga pot). Backend: migracija 016
  (`friend_requests`, `friendships`, `users.share_plans_with_friends`), poti `/users/search`, `/me/friends*`. Prijateljstvo je
  simetrično; o tujem uporabniku se razkrije samo id, uporabniško ime in avatar (invarianta I11).
  *vir/dokaz*: Martinovo naročilo v pogovoru 20. 9. (slika »Your crew is going«). *velja dokler*: ni odločeno drugače o
  privzeti vrednosti deljenja načrtov in načinu iskanja (glej STATE, predpostavke 20. 9.). *nadomeščena z*: —
- 2026-09-21: **Profil lastnika kluba je klubski, profil zaposlenih osebni** (Luka, Martin na dopustu): racun z vlogo
  `business` (lastnik) v zavihku Profile vidi logo in ime kluba, »Edit your page«, Dashboard, Events, My team, Settings
  (Club info, Password and security, Switch to personal account) — brez Tickets/My friends/My Clubs, ker je racun za
  klub, ne za zuranje; preklop na osebni obraz je mozen (in nazaj v My Account). Zaposleni (manager, vratar) imajo
  se naprej osebni profil in svoj klub pod My Clubs (Martin, 20. 9., ostane). Sveze odobren lastnik brez kluba dobi
  obrazec (ime, logo, naslov, mesto, zanri, starost) → `POST /clubs`, klub je takoj na Home. »Withdraw« iz Figme se
  ne gradi (Stripe, glej zgoraj). *vir/dokaz*: Lukovo narocilo 21. 9. + Figma »settings«. *velja dokler*: Martin ne
  potrdi ali odloci drugace (odstopa od njegove odlocitve 20. 9. samo pri lastniku). *nadomeščena z*: —
- 2026-09-21: **Samo dva sloga vrstic v aplikaciji** (Luka): `OutlyMenuRowButton` (ikona + naslov, cela vrstica gumb)
  in `OutlyInfoCardButton` (naslov kartice, ikona, vrednost, moder Edit, opomba). `OutlySettingsRow` in lokalna
  `vrstica` v MyClubDetailView sta odstranjeni; stikala ostanejo `OutlySettingsToggleRow`. *vir/dokaz*: Luka 21. 9.
  (posnetki treh razlicnih gumbov). *velja dokler*: — *nadomeščena z*: —
- 2026-09-21: **»Kot Revolut«: Search in Profile lezita nad zamegljenim, zamrznjenim domacim zaslonom** (Luka).
  Sistemska spodnja vrstica ostane (Martin, 20. 9., PR #11); ucinek je narejen s posnetkom zaslona ob preklopu
  zavihka (`UIApplication.posnetekZaslona`, `HomeSnapshotBackground`) in okoljem `prosojnoOzadje`, ki vsem zaslonom
  v teh dveh zavihkih (tudi potisnjenim) vzame crno ozadje (`.outlyOzadje()` namesto `.background(Color.black)`).
  Map ostane pravi zemljevid. *vir/dokaz*: Luka 21. 9. *velja dokler*: Martin ne rece drugace (20. 9. je zavrnil
  lastno vrstico, ne ucinka). *nadomeščena z*: —
- 2026-09-21: **Obvestilo o prejeti vstopnici** (Martin): ko prijatelj pošlje vstopnico, prejemnik v meniju obvestil (zvonec)
  vidi »X sent you a ticket for Y«; dotik odpre Tickets in obvestilo označi kot prebrano. Backend: migracija 017
  (`ticket_transfers.seen_at`), `GET /me` polje `pending_received_tickets`, `GET /me/tickets/received`,
  `POST /me/tickets/received/:id/seen`. Prenosi pred migracijo se štejejo za prebrane. Meni obvestil je brez spodnjih
  gumbov My Clubs / My Friends (oba sta v profilu). *vir/dokaz*: Martinovo naročilo 21. 9. *velja dokler*: ni potisnih
  obvestil (APNs) — takrat je to isti vir podatkov, samo še push. *nadomeščena z*: —
- 2026-09-14/15: Stran kluba: slideshow do 3 slik + video kluba (`gallery_urls`, `video_url`, 015); zaslon dogodka po Lukovih navodilih
  (plakat dogodka čez vrh, naslov pod pasico, gumb za nakup prosojen na pasici).
- 2026-09: Slike klubov v produkciji so ZA DEMO (prave s spletnih strani klubov). Pred pravim zagonom jih zamenjajo slike,
  ki jih dajo klubi (dovoljenje!).
- 2026-09: **Testni način plačil**: dokler `STRIPE_SECRET_KEY` ni nastavljen, je naročilo takoj `paid` z oznako `test_`;
  aplikacija to jasno kaže. Ob nastavitvi ključa testna pot vrne 503.
  *velja dokler*: `STRIPE_SECRET_KEY` ni nastavljen na Renderju — takrat se ta pot izklopi sama, brez spremembe kode.
  *nadomeščena z*: 2026-10-03 »Stripe Checkout + Connect« (spodaj): s SANDBOX ključem testna pot ostane za klube brez Stripa.
- 2026-10-03: **Stripe Checkout + Connect Express** (issue #19, `placila_stripe.js`, migracija 030). Destination charge z
  `application_fee_amount` (10 %) **in `on_behalf_of` = račun kluba**, da je klub tudi »business of record« (pravna analiza
  1. 10. 2026, tveganje V1: brez `on_behalf_of` bi bil to NEXT DIMENSIONS). Naročilo je `pending`, dokler ga ne potrdi
  **webhook** (`checkout.session.completed`) ali pospravljalec, ki sejo preveri pri Stripu; odjemalec plačila nikoli ne potrdi sam.
  Seja traja 30 min, zaloga/miza je med tem rezervirana. Način: brez ključa = test; `sk_test_` + klub s `charges_enabled` = Stripe,
  klub brez Stripa = še vedno test (demo klubi in TestFlight delajo naprej); `sk_live_` + klub brez Stripa = 409.
  API različica pripeta (`2025-03-31.basil`). *vir/dokaz*: Martin v pogovoru 3. 10. 2026 (»danes rabi biti testni Stripe«),
  sandbox »Outly sandbox« z vklopljenim Connect (marketplace), `_testi/test_stripe.js` · *velja dokler*: je Outly posrednik ·
  *nadomeščena z*: —

- 2026-09-29: **Spletna aplikacija (PWA) na `outly.si/app`, v repozitoriju `outly_webpage`, brez builda** (Martin, izbira A).
  Isti backend, baza in prijava kot iOS - nov odjemalec za ljudi brez aplikacije (deljena povezava na dogodek) in za Android
  (Android aplikacije ni). Preact + htm kot ES moduli, gostovani v `vendor/`; vse `/app/*` streze ena lupina (`_redirects`).
  Posledica: ena domena = ena seja z outly.si (prijava velja na strani in v spletni aplikaciji), en deploy (Cloudflare Pages),
  pravilo "brez builda" ostane. Zavrnjena B: nov repo z Vite/TypeScript na `app.outly.si` (nov deploy, poddomena, locena seja).
  Faze: 1 ogrodje + prijava + Home/Search/dogodek/klub (+ nakup v testnem nacinu in vstopnice s QR), 2 profil/prijatelji/obvestila,
  3 zemljevid, 4 poslovni obraz + skener, 5 PWA do konca. Gumb "Open web app" na outly.si in pametni banner za iOS: na koncu.
  *vir/dokaz*: Martinov odgovor v pogovoru 29. 9. 2026 (tocke 1-7), specifikacija zaslonov iOS -> API v opisu outly_webpage PR ·
  *velja dokler*: spletna aplikacija ne preraste nacina brez builda (npr. vec razvijalcev, potreba po tipih) - takrat znova B ·
  *nadomeščena z*: —
- 2026-09-29: **Prijava v spletni aplikaciji s kodo iz maila, kot iOS** (ne s povezavo). Zato Supabase Redirect URL-ji za `/app`
  niso potrebni (Martin: "naredi, kar je logicno"). Registracija ima kljukico 15+ in pogoje (kot outly.si, `terms_version`).
  *velja dokler*: Supabase mail vsebuje kodo (`{{ .Token }}`) - brez nje bi iOS in splet obstala.
- 2026-09-29: **Neprijavljeni v spletni aplikaciji vidijo klube, dogodke in cene** (Martin: DA). Backend jih ze vraca javno;
  "I'm in", Follow in nakup zahtevajo prijavo (po prijavi uporabnik ostane na istem dogodku).
- 2026-09-29: **Zemljevid na spletu: Protomaps (PMTiles), gostimo sami** (Martin: "probaj protomaps"), ne MapTiler/Stadia (brezplacno
  samo nekomercialno; 25 $ oz. 20 $ na mesec). OSM javni strežnik ploscic za aplikacije ni dovoljen. Kje bo datoteka (repo/R2),
  se odloci v fazi 3; ce rabi Cloudflare R2, ga vklopi Martin. Lokacijo kluba lastnik na spletu oznaci s klikom na zemljevid
  (brez placljivega geokoderja; Martin: "okej"). *velja dokler*: kolicina ploscic ali Cloudflare pogoji tega ne onemogocijo.
- 2026-09-29: **Politika zasebnosti za spletno aplikacijo**: agent pripravi predlog (localStorage, lokacija na gumb, kamera za
  skener, service worker), objava sele po Martinovem DA na konkretno besedilo.
- 2026-09-29: **QR skener vstopnic je SAMO v iOS aplikaciji, ne v spletni** (Martin: "qr skener bo samo mozen na aplikaciji ne
  prek webappa"). Splet v fazi 4 kaze poslovni del brez skenerja in brez rocnega "Check in"; vstopnice dogodka so samo za ogled,
  vratar na spletu vidi samo opombo. Posledica: politika zasebnosti za splet ne omenja kamere; `POST /business/tickets/scan`
  klice samo iOS. Spreminja nacrt faz zgoraj ("4 poslovni obraz + skener" -> brez skenerja).
  *vir/dokaz*: Martinovo sporocilo v pogovoru 29. 9. 2026 · *velja dokler*: Martin ne rece drugace · *nadomeščena z*: odlocitev
  "QR skener tudi na spletu" (29. 9. 2026, spodaj)
- 2026-09-29 (kasneje isti dan): **QR skener vstopnic je TUDI v spletni aplikaciji** (Martin: "dodej se za skeniranje qr kod
  ker mogoce bo tisti na vratih imel androida in ne bo mogel naloziti aplikacije"). Nadomesti zgornjo odlocitev.
  Splet: `/app/business/:klub/scan` za vse vloge v klubu (tudi vratar), rocni "Check in" pri vstopnicah dogodka (kot iOS).
  Kamera v brskalniku (getUserMedia), dekodiranje na napravi (BarcodeDetector ali jsQR) - na strezik gre samo vsebina kode
  prek obstojecega `POST /business/tickets/scan`; backend nespremenjen. Politika zasebnosti za splet mora omeniti kamero
  (osnutek posodobljen).
  *vir/dokaz*: Martinovo sporocilo v pogovoru 29. 9. 2026; outly_webpage PR #18 · *velja dokler*: Martin ne rece drugace ·
  *nadomeščena z*: —
- 2026-10-01: **VIP mize s tlorisom** (Martin). Klub v spletni aplikaciji (`/app/business/:klub/vip`) enkrat narise tloris (mreza
  celic; bar, oder, DJ, plesisce, vhod, WC, napis, stena) in mize (oznaka, oblika, 1-20 sedezev, privzeta cena) ter vpise bottle
  pakete (npr. "Jameson 0,7 l" + "4x Red Bull, 1 l orange juice"); pri vsakem dogodku VIP vklopi, ceno mize po zelji prepise ali
  mizo izklopi. Kupec na dogodku (splet in iOS) klikne prosto mizo, izbere paket (vstet v ceno mize) in kupi: dobi N VIP vstopnic
  (N = sedezi mize), vsaka s svojo QR kodo, in jih z obstojecim prenosom razdeli prijateljem. Vratar/bar ob skenu in v seznamu
  rezervacij vidi VIP, mizo in paket. Placilo kot pri vstopnicah (testni nacin, takoj `paid`). Urejevalnik tlorisa je SAMO na
  spletu (iOS ga nima, pride pozneje). Backend: migraciji 025 (shema, invarianta I13) in 026 (demo tloris, 6-10 miz in 4-6 paketov
  za Velvet, Nexus, Mirage, Mansion, Olie; 026 NI samo INSERT: vstavi mize in pakete, na obstojecih vrsticah pa izpolni nova stolpca `clubs.floor_plan` NULL -> tloris in `events.vip_enabled` FALSE -> TRUE), poti `GET /events/:id/vip`, `POST /events/:id/tables/:tableId/orders`,
  `GET|PUT /business/vip`, `GET|PUT /business/events/:id/vip` (ARCHITECTURE, razdelek "VIP mize").
  *vir/dokaz*: Martinovo narocilo v pogovoru 1. 10. 2026, `_testi/test_vip.js` (251 trditev), invarianta I13 ·
  *velja dokler*: ni drugace odloceno; ko pride Stripe, nakup mize dobi PaymentIntent kot vstopnice (isti mehanizem) ·
  *nadomeščena z*: —
- 2026-10-01: **Predpostavke agenta pri VIP mizah** (iz specifikacije; Martin jih ni izrecno odlocil, spremeni jih lahko brez
  posledic za shemo, razen prve): (1) VIP vstopnice **ne stejejo** v `events.capacity` / `sold_count` - mize so lastna zaloga, vsaka
  miza enkrat na dogodek (I13); razprodan dogodek zato se vedno proda mize. (2) **Paket je obvezen**, ce ima klub vsaj en aktiven
  paket; klub brez paketov prodaja mize brez paketa (`package_id` NULL). (3) **Okno prodaje mize = isto kot za vstopnice**
  (objavljen dogodek, klub viden, zacetek v prihodnosti, `sales_open_at` / `sales_close_at`); mize se po zacetku se vidijo
  (`on_sale: false`), kupiti se ne da. (4) Mize in paketi se **arhivirajo, ne brisejo** (narocila hranijo posnetek imen).
  (5) `GET /business/sales`: `tickets_sold` steje samo navadne vstopnice, mize posebej (`tables_sold`), `gross_cents` jih
  vkljucuje; enako v adminovih financah. (6) Provizija 10 % velja tudi za mize. (7) Cena mize je strop 100.000 EUR (tipkarske napake).
  *vir/dokaz*: specifikacija VIP miz 1. 10. 2026, `_testi/test_vip.js` · *velja dokler*: Martin ne rece drugace ·
  *nadomeščena z*: —

- 2026-10-02: **VIP miza s paketom pijace: nakup in prenos od 18 let** (issue #102, pravna analiza pravnika 1. 10. 2026, ZOPA 7/1: alkohola
  se ne sme prodati ali dati osebi pod 18 let). Strezniska preverba starosti je gledala samo `min_age` dogodka, zato je lahko miza s
  steklenico sla 16-letniku na dogodku 16+. Polja "vsebuje alkohol" v shemi ni (`bottle_packages`: ime, opis), zato **vsak paket stejemo
  kot alkohol** (najmanjsa varna resitev brez migracije): za mizo Z IZBRANIM PAKETOM nakup (`POST /events/:id/tables/:tableId/orders`)
  in prenos vsake njene vstopnice (`POST /tickets/:id/transfer`) zahtevata starost >= max(`min_age` dogodka, 18); brez datuma rojstva 403
  (kot pri `min_age`). Miza BREZ paketa (klub brez paketov) in navadne vstopnice ostanejo pri `min_age` dogodka. `GET /events/:id/vip`
  vrne novo polje `package_min_age`. Pozneje, ce bo potrebno razlikovati brezalkoholne pakete: stolpec `bottle_packages.contains_alcohol`
  (migracija, privzeto TRUE) in klub ga oznaci sam; brez tega ostane vsak paket alkohol. Predpostavka (Martin je ni izrecno potrdil):
  miza brez paketa ne pomeni nakupa alkohola prek Outly. *vir/dokaz*: issue #102, `_testi/test_vip_starost.js` (nakup in prenos: 17 let,
  tocno 18, brez datuma, strozja meja dogodka) · *velja dokler*: Martin ali pravnik ne rece drugace ·
  *nadomeščena z*: —

- 2026-10-04: **Rezervacija VIP mize po telefonu** (Martin v pogovoru 4. 10. 2026: »rezervacija po telefonu kot plus, brez potrditve kluba«).
  Ce gost klub poklice in rezervira mizo, jo klub (owner, manager) sam oznaci kot zasedeno na dogodku (`POST|DELETE /business/events/:id/tables/:tableId/hold`,
  tabela `table_holds`, migracija 032); prek Outly je potem nihce ne more kupiti. Placilo gre mimo Outly, zato rezervacija NI narocilo: ne steje v
  `GET /business/sales` in adminove finance, nima vstopnic, sken se ne spremeni. Obstojeci nakup ostane brez potrditve kluba (Martin).
  **Odlocitve agenta (Martin jih ni potrdil; spremenljive brez posledic za nakup):** (1) rezervacija je dovoljena tudi za mizo, ki je na dogodku
  izklopljena, in na dogodku, kjer VIP ni vklopljen (klub tloris uporablja tudi samo za telefonske rezervacije); javno se izklopljena miza z
  rezervacijo pokaze kot zasedena, kot prodana. (2) Ime gosta (1-60 znakov) in opomba (0-200) sta v poslovnem pogledu
  (`GET /business/events/:id/vip`, vse vloge v klubu, tudi vratar), NIKOLI v javnih odgovorih ali v odgovorih kupcu. (3) **Hramba osebnega podatka:**
  gost ni uporabnik Outly, ime je prosto besedilo; rezervacije dogodka, ki se je koncal pred vec kot 24 h (`end_at`, sicer `start_at` + 12 h), brise
  pospravljalec v procesu (vsako uro, `REZERVACIJE_CISCENJE_MS`); brisanje dogodka jih pobrise (CASCADE). **Odprto za `pravnik`:** ali politika
  zasebnosti za splet in iOS omenja ime gosta, ki ga vnese klub (klub je upravljavec, Outly obdelovalec?), rok hrambe (24 h po koncu je predpostavka)
  in dejstvo, da izvoz baze (dnevna kopija v R2, do 30 dni) hrani imena do izteka kopij. Ime gosta se ne zapisuje v dnevnik. (4) Hkratnost: glej
  ARCHITECTURE, I13 (zaklep vrstice `club_tables`, nakup `FOR SHARE`, rezervacija `FOR NO KEY UPDATE`).
  *vir/dokaz*: Martinovo sporocilo v seji menedzerja 4. 10. 2026 (samo: »rezervacija po telefonu kot plus, brez potrditve kluba«),
  `_testi/test_rezervacija_telefon.js`, I13 · *velja dokler*: Martin ali pravnik ne rece drugace (pravni pregled hrambe se ni opravljen) ·
  *nadomescena z*: —

## Oblikovanje

- Figma datoteka `XeVmPgY0LDGkNcQGBkNDbg` (stran »App«, ~147 zaslonov 393×852) je merodajna za postavitev,
  a ne 1:1: temna tema, modra `#4C76FF` samo na glavnem gumbu (ne na velikih ploskvah), »prijazno za oči«,
  brez vijolično-modrih prelivov, brez emojijev kot ikon, ena poudarjena stvar na zaslon, 8-pt mreža, SF Symbols.
- Vsaka kartica mora nekam voditi. Slike vedno `Color.clear.overlay(img.resizable().scaledToFill()).clipped()`.
- 2026-09-20: **Prenova domačega zaslona iOS** (Martinova specifikacija, outly-app PR #10, build 48): (1) ozadje temno
  mornariški preliv z mehkima modrima sijema, ki se premikata ob drsenju, brez oblik; (2) Home ostane pod Search/Map/Profile
  zamegljen in potemnjen, izbrani zaslon pride kot plast (sistemski `TabView` → `ZStack` + `OutlyTabBar`); (3) glava:
  avatar levo, logo na sredini, zvonec desno z modro značko »1« / »1+«; (4) »Where to?« je en dvodelni okvir: iskanje levo,
  filter desno, tanko ločilo — filter ni ločen gumb; (5) kartice dogodkov: podatki v spodnjem pasu znotraj plakata
  (levo zamegljeno naslov + klub · čas, desno modra cena), plakat nespremenjen, kartica nižja; (6) Filtri: City, »Use my
  preferences« (stikalo naloži žanre, razdaljo, starost, ceno iz profila), žanri, razdalja, starost, cena; modra za aktivna
  stanja; (7) My Account: Language in Notifications pod novim **Preferences** (My preferences, Notifications, Language),
  isti slog kot obstoječi podzasloni. *vir/dokaz*: Martinovo naročilo 20. 9. (točke 1–7), design kanvas (ARCHITECTURE →
  Oblikovanje). *velja dokler*: Martin ne preveri builda 48 na napravi; prehodi z blurom so prvi osumljenec pri težavah.
  *nadomeščena z*: točka (2) — 2026-09-20 pozneje: Martin je vrnil **sistemsko spodnjo vrstico** (outly-app PR #11, build 50),
  `OutlyTabBar` in `ZStack` sta umaknjena; učinek zamegljenega Home se je vrnil 21. 9. kot »Kot Revolut« (prekrivne plasti nad
  TabViewom, glej zgoraj). Točke (1), (3)–(7) veljajo naprej.
- 2026-09-29: **Prehod Home <-> Search/Profile ostane "kot Revolut", a animira posnetke zaslona, ne zive vsebine**
  (agent, po Martinovi prijavi "steka / 15 fps"). Videz enak (vsebina raste iz polja "Where to?" oz. avatarja, Home se
  zamegli), izvedba: zamrznjene slike (outly-app #34, #35). Sistemski prehod bi bil vedno gladek, a bi opustil Martinovo
  izbiro — brez njegovega DA se ne menja. *vir/dokaz*: Martinov posnetek zaslona 29. 9. (casi slicic), Martin na napravi
  po #34: "veliko bolje" · *velja dokler*: Martin ne rece, da je se vedno premalo gladko (takrat predlagaj sistemski
  prehod) · *nadomeščena z*: 2026-09-29 (pozneje), spodaj.
- 2026-09-29 (pozneje): **Prehod Home -> Search/Profile animira ZIVO vsebino (samo skala), ne posnetka** (outly-app #39).
  Posnetki (#34-#38) so spremenili videz "kot Revolut" (Martin dvakrat: "ni una animacija k je bla prej"). Ziva vsebina
  raste brez animirane prosojnosti, oster Home pojema nad njo. *vir/dokaz*: Martinova posnetka zaslona po #38 (vsebina ni
  rasla) in po #39 (takojsen zacetek, 40-60 fps, pravi videz) · *velja dokler*: Martin ne rece, da je premalo gladko
  (takrat predlagaj sistemski prehod) · *nadomeščena z*: —
- 2026-09-20: Spletna stran ima razdelek **Points** (»Earn points before launch«) med Preview in Waitlist, po Martinovi
  predlogi plakata; besedilo koristi je Martinovo (glej odločitev o unovčenju točk zgoraj).
- 2026-09-20: Pravilo »modra samo na glavnem gumbu« se v praksi bere kot **modra je barva poudarka** (aktivni zavihek,
  izbrani čip, stikalo, cena, fokus), **polna modra ploskev samo na glavnem gumbu**. Pravilo »8-pt mreža« koda ne drži
  (najpogostejši razmiki 10, 12, 14, 18); nova koda naj sledi obstoječim vrednostim, ne dokumentu. *vir/dokaz*: izvleček
  design sistema iz kode 19. 9. (kanvas, tabla »Analiza«).

## Infrastruktura (odločeno 14. 9. 2026 po sestanku z investitorji)

- Render web service → paket 7 USD (0,5 CPU, 512 MB) je dovolj za 500+ uporabnikov.
  *vir/dokaz*: stresni test 11. 9. 2026 — 616 req/s pri 40 vzporednih, brez napak.
  *velja dokler*: teče **ena instanca** backenda; ob drugi instanci padeta omejevalnik poskusov v pomnilniku (S-02)
  in ta izračun zmogljivosti. *Dopolnilo 2. 10. 2026*: omejevalnik je od migracije 027 v PostgreSQL (spodaj), zato ta pogoj
  za omejevalnik ne velja več; za izračun zmogljivosti (CPU/RAM ene instance) velja še naprej.
- Render baza → plačljivi paket **pred 7. 10. 2026** (brezplačna se izbriše; januarja se je to že zgodilo).
  *velja dokler*: 7. 10. 2026 — po tem datumu ni več odločitev, ampak izgubljena baza.
  **Izvedeno 30. 9. 2026** (Martin): baza `0.1c-256mb` (6 $), web service Starter `0.5c-512mb` (7 $). Za webapp (`outly.si/app`)
  dodatnega gostovanja ni treba: statika na Cloudflare Pages, API isti backend.
  *vir/dokaz*: Stresni test #2/#3 (baza CPU ~0, RAM ~20 %; web CPU ~34 % na Starterju, 0 % napak), Render API.
- 2026-10-02: **Omejevalnik poskusov je v PostgreSQL (tabela `omejitve`, UNLOGGED); ob njegovi okvari po poti: fail-open za `ogled` in
  `iskanje`, lokalni števec v procesu (staro vedenje) za nakup in prenos, fail-closed (503 + `Retry-After`) za brisanje računa in prošnje;
  skeniranje omejevalnika sploh nima.** Razlog: števec v pomnilniku se je ob drugi instanci ali deployu ponastavil (issue #24). Redis bi pomenil
  nov plačljiv servis (7+ $/mesec), ena UPDATE vrstica v bazi pa zadošča. Fail-open pri ogledu in iskanju, ker omejevalnik tam varuje samo števec
  in gnetenje iskanja. Nakup in prenos: fail-closed bi ob navalu (zasičen ali počasen pool omejevalnika, povezava 2 s) zavrnil kupce, čeprav glavni
  pool dela, fail-open pa bi pustil neomejeno rezerviranje zaloge (nakup rezervira vstopnice že ob vstavitvi) — zato degradirano, ne zaprto: iste meje,
  a števec samo v procesu. Brisanje (nepovratno) in prošnje (maili) ostanejo fail-closed: okvara omejevalnika je skoraj vedno okvara baze, kjer bi pot
  tako ali tako padla. Ključ v bazi je HMAC-SHA256(pot:meja:okno:IP) (HKDF iz `QR_SECRET`/`JWT_SECRET`, nove skrivnosti ni; IPv6 na /64): IP je osebni
  podatek, golo sha256 pa bi se razbilo z naštevanjem IPv4; meja v ključu prepreči, da bi pot z drugo mejo števec zmanjšala ali podedovala tujo blokado.
  Tabela je UNLOGGED (po padcu baze se meje ponastavijo, kot prej ob vsakem deployu) in ni v izvozu baze. Hashi IP-jev ostanejo do 1 h v bazi =
  psevdonimizacija: pregled politike zasebnosti (pravnik/Martin).
  *vir/dokaz*: [issue #24](https://github.com/Djurdje/outly-backend/issues/24), `_testi/test_omejevalnik.js`, invarianta I15; zmogljivost: LOKALNA meritev
  (PG16 na isti napravi, `_orodja/merjenje_omejevalnika.js`, ~2.100 omejenih klicev/s na instanco pri 1000 vzporednih povezavah) — NE na Renderjevi bazi
  `0.1c-256mb`, kjer bo počasneje; treba izmeriti po deployu ·
  *velja dokler*: omejeni klici ostanejo pod ~1.000/s na instanco in je baza majhna; ob več ali opaznem CPU baze zaradi `omejitve` → Redis ·
  *nadomeščena z*: — (nadomešča omejevalnik v pomnilniku procesa, S-02)
- 2026-09-16: Apple Developer: Martin ima **Individual račun**; pozneje App Transfer na NEXT DIMENSIONS. Bundle ID `si.outly.app`,
  ime v App Store Connect »Outly - Nightlife« (»Outly« zasedeno). **Distribucija samo prek TestFlighta** (podpis v GitHub Actions s cloud
  signing, API ključ v secrets, nič v repu); Sideloadly/AltServer se opustita. Runner `macos-26`; `MARKETING_VERSION` dviguje Martin.
  *velja dokler*: je račun **Individual** (App Transfer na NEXT DIMENSIONS zahteva nove ključe v secrets in nov dogovor o vlogah)
  in dokler Apple sprejema iOS 26 SDK (`macos-26`).
- 2026-09-16: iOS PR-ji morajo skozi prevod za simulator v Actions pred merge-om; TestFlight upload samo ob pushu v `master`.
- 2026-09-20: **Razvojni certifikat za `Gradnja iOS` je v GitHub secrets (`IOS_DEV_CERT_P12` base64 + `IOS_DEV_CERT_PASSWORD`),
  ne več »Xcode si ga naredi sam«.** Razlog: cloud signing je na vsakem svežem runnerju ustvaril nov Apple Development
  certifikat (zasebni ključ se z runnerjem izgubi) in po nekaj gradnjah zadel Applovo omejitev — TestFlight je stal.
  Certifikat je narejen namenoma za CI (»Outly CI«, CSR z OpenSSL na Windowsu, brez Maca), zato ni vezan na noben razvijalčev
  računalnik. Distribucijski podpis ostaja cloud-managed prek ASC API ključa. Odločil Martin (v pogovoru, 20. 9.).
  *vir/dokaz*: zagon `Gradnja iOS` #53 rdeč (»maximum number of certificates«), #54 zelen po PR outly-app #13; INCIDENTI 2026-09-20.
  *velja dokler*: certifikat velja (**eno leto, do ~20. 9. 2027**) in dokler je Apple račun Individual (App Transfer = nov
  certifikat pod novim teamom). Ob poteku: nov CSR → nov .p12 → zamenjava obeh secrets; postopek v outly-app `CLAUDE.md`.
  *nadomeščena z*: —
- Stripe račun odpre Luka za NEXT DIMENSIONS; Connect Express za klube; ključi `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET`
  na Render nastavi Martin/Luka; webhook `/stripe/webhook`, idempotentnost prek `orders_pi_key`.
  *velja dokler*: je Outly posrednik in ne prodajalec (destination charges).
- Supabase Pro (25 USD) pred javnim zagonom (kopije). *velja dokler*: brezplačni paket zadošča —
  torej do javnega zagona oziroma do trenutka, ko je izguba prijav nesprejemljiva.
- Spletna stran: Cloudflare Pages (od 10. 9. 2026), ne GitHub Pages (komercialna raba ni dovoljena).
  *vir/dokaz*: pogoji uporabe GitHub Pages (prepoved komercialne rabe). *velja dokler*: stran nima builda in
  je vse v repu javno (zato v repu nič internega).

- 2026-09-22: **Dogodek ima stanje `ended`; posnetek dogodka samo na treh najbolj popularnih.** Dogodek je končan, ko
  mine `end_at`, in če ga klub ni vpisal, `start_at + 8 h` (klubski večer se ne konča ob uri začetka). Novo polje odgovora
  `lifecycle` (`upcoming` | `live` | `ended`); staro `time_status` ostane nespremenjeno, ker ga berejo aplikacije na telefonih.
  Končani dogodki izpadejo iz `GET /me/friends/plans` (dogodek, ki nocoj teče, ostane). Na končan dogodek sme klub naložiti
  **posnetek** (`recap_video_url`), ki na strani kluba zamenja plakat — a samo na **treh** najbolj popularnih končanih dogodkih
  kluba (po prodanih vstopnicah), sicer bi stran kluba nalagala poljubno mnogo videov. Meja je na strežniku (invarianta **I12**).
  Odločil Martin (v pogovoru, 22. 9.).
  *vir/dokaz*: `_testi/test_sledenje.js`, invarianta I12 v ARCHITECTURE ·
  *velja dokler*: je posnetek na Cloudinaryju in ga stran kluba predvaja samodejno (z ročnim zagonom bi bila meja 3 lahko višja) ·
  *nadomeščena z*: —
- 2026-09-22: **Klubu se sledi (Follow), ne lajka.** Na strani kluba je gumb **Follow** in ob imenu število sledilcev;
  sledilec dobi obvestilo, ko klub objavi dogodek (`club_follows`, `club_event_notifications`, migracija 019).
  Srček (priljubljeno) ostane **samo na dogodkih** — lajkanja kluba ni in ne bo, ker bi bili dve skoraj enaki dejanji
  na istem zaslonu in nobeno ne bi bilo jasno. Odločil Martin (v pogovoru, 22. 9.).
  *vir/dokaz*: `_testi/test_sledenje.js` · *velja dokler*: ni potisnih obvestil (APNs); ko bodo, sledenje postane
  tudi naročnina na push, ne samo na zvonec · *nadomeščena z*: —
- 2026-09-23: **"I'm in" / zanimanje za dogodek.** Uporabnik na dogodku oznaci "I'm in" (zanimanje); prijatelji
  to vidijo poleg tistih, ki dogodek ze imajo vstopnico ("going"). "Going" se NE shranjuje — izpelje se iz
  veljavne vstopnice (isti mehanizem kot v `GET /me/friends/plans` od 20. 9.); shranjuje se samo "interested"
  (`event_interest`, migracija 020). `PUT|DELETE /events/:id/interest`, `GET /events/:id` (`my_plan`,
  `friends_going`, `friends_interested`), `GET /me/friends/plans` (novo polje `interested`, unija dogodkov),
  `GET /me/plans`. Zasebnost enaka kot pri "going" (invarianta I11): samo prijatelji s
  `share_plans_with_friends = true`. Odlocil Martin (v pogovoru, 23. 9.).
  *vir/dokaz*: Martinov pogovor 23. 9., `_testi/test_zanimanje.js` (38 testov) · *velja dokler*: — · *nadomeščena z*: —
- 2026-09-25: **"Check activity" na nadzorni plosci kluba.** Nova tabela `view_counts` (migracija 021):
  agregiran dnevni stevec klikov na profil kluba in na dogodke, brez IP-ja, brez uporabnika, brez casa
  posameznega klika — GDPR: samo stevilka. `POST /views` je javna pot (brez zetona, omejena po IP na
  600/h), neveljaven ali skrit cilj tiho vrne 204 brez zapisa. `GET /business/activity` (owner/manager):
  kliki na profil/dogodke (skupaj in zadnjih 7 dni), sledilci in aktivnost ekipe (skeni po clanu).
  `GET /business/team/:userId/scans`: skeni clana po dogodkih. `GET /business/sales` dobi neobvezen
  `?range=week|month|year` -> polje `series` (dnevni/mesecni kosi, vsi vkljuceni tudi z 0) in `events[].interested_count`;
  brez `range` je odgovor nespremenjen (star odjemalec). Odlocil Martin (v pogovoru, 25. 9.).
  *vir/dokaz*: Martinov pogovor 25. 9., `_testi/test_aktivnost.js` (55 testov) · *velja dokler*: — · *nadomeščena z*: —
- 2026-09-22: **Stran kluba kaže slideshow, ne pasice.** Pasica (`banner_url`) se iz urejanja kluba umakne; stolpec v bazi
  in polje v odgovoru **ostaneta** (stari odjemalci, obstoječi klubi brez galerije še naprej vidijo pasico prek
  `APIClub.slideshowUrls`). Novi klubi nalagajo samo slideshow (do 3 slike). Odločil Martin (v pogovoru, 22. 9.).
  *velja dokler*: obstaja vsaj en klub, ki ima pasico in nima galerije · *nadomeščena z*: —
- 2026-10-01: **Sken brez povezave: QR v2 z Ed25519, ključ izpeljan iz `QR_SECRET`** (Martinova zahteva: sken na vratih ne sme pasti
  nikoli, 1000+ hkratnih uporabnikov; issue #86). HMAC za preverjanje na telefonu ne pride v poštev (skrivnost bi morala biti na telefonu).
  Zato podpis z javnim ključem; ključni par je HKDF iz obstoječe skrivnosti (brez nove spremenljivke, brez Martinovega dela), stare kode v1
  veljajo naprej. Strežnik ostane razsodnik (`scan-batch`); dva telefona brez povezave lahko spustita isto vstopnico — sprejeto tveganje.
  *vir/dokaz*: issue #86, backend PR "Sken brez povezave", `_testi/test_sken_brez_povezave.js` · *velja dokler*: — (rotacija ključa =
  zamenjava `QR_SECRET`, razveljavi vse kode) · *nadomeščena z*: —
- 2026-10-02: **Odločitev agenta (predpostavka), Martin je ni potrdil:** javni seznami se predpomnijo v procesu, 3 s, brez Redisa; `Cache-Control: private` samo na osebnih različicah (issue #114; zanesljivost: 1000+ hkratnih
  ogledov, sken na vratih ne sme pasti). Predpomni se samo javni del odgovora (ključ brez žetona), osebna polja se računajo posebej (I17).
  Razveljavitev ob zapisu v procesu (izjeme: ARCHITECTURE »Javni predpomnilnik«); zaostanek drugih instanc največ TTL agent sprejema kot predpostavko. Zunanji predpomnilnik (Redis, CDN pravila) bi
  stal denar ali nastavitve računov, zdaj ni potreben. *vir/dokaz*: PR #111 (meritev), PR tega commita (pred/po), `_testi/test_javni_predpomnilnik.js` ·
  *velja dokler*: teče ena instanca; pri več instancah ali CDN-u pred API-jem preglej razveljavitev · *nadomeščena z*: —
- 2026-10-02: **Idempotentni ključ nakupa** (glava `Idempotency-Key`, UUID; issue #112, I18, migracija 028). Dodajanje, ne brisanje: brez glave vse kot
  prej. Odločitve agenta (Martin jih ni potrdil, vse povratne): (1) **ponovitev vrne 201 z istim naročilom in TRENUTNIM stanjem** (+ `Idempotent-Replayed: true`; po skenu `used`, po prenosu drug imetnik),
  ne 200; neaktivno naročilo (vrnjeno, preklicano) 409 `order_not_active`, ker to ni uspeh: odjemalca (iOS `200...299`, splet `ok`) status ne razlikuje in oba ob uspehu pokažeta vstopnico, posebna pot za ponovitev bi bila
  nepotreben vzorec za napako; (2) **hkratni zahtevek počaka in dobi isti rezultat** (v istem procesu v pomnilniku, brez mesta v semaforju I16;
  med instancami ga vrsti `pg_advisory_xact_lock` na ključ), 409 `request_in_progress` + `Retry-After: 2` šele po `IDEMPOTENCA_CAKANJE_MS`
  (10 s): odjemalec brez posebne logike ob timeoutu in ponovitvi tako dobi naročilo, ne napake, 409 bi ga prisilil v lastno zanko ponavljanja;
  (3) **neuspeh se ne zapomni** (kot Stripe bi lahko vrnil staro napako, a tu je ponovni poskus po 503/409 ravno namen); (4) vsebina ključa =
  dogodek, količina, miza, paket (cena ne), primerjava z vrstico naročila, ne s shranjenim odtisom; (5) ključ je vezan na uporabnika.
  Migracija: nullable stolpec + delni unikaten indeks, `CREATE INDEX` brez `CONCURRENTLY` (ne gre v transakciji `migrate.js`; izmerjeno 62 ms pri
  300.000 naročilih). *vir/dokaz*: issue #112, `_testi/test_idempotenca.js` (na stari kodi pade), ARCHITECTURE I18 · *velja dokler*: trajno; pri
  Stripe plačilih (#19) se isti ključ prenese na PaymentIntent · *nadomeščena z*: —

## Način dela (odločeno 16. 9. 2026)

- Vsi trije repozitoriji imajo `CLAUDE.md` + `.claude/agents/`; ta datoteka in `STATE.md` (v backend repu) sta skupni
  možgani vseh agentov. Delo teče prek **cloud sej Claude Code** (claude.ai/code, mobilna aplikacija) in PR-jev;
  `main`/`master` sta zaščitena, merge šele po zelenem CI. Neposredno potiskanje v produkcijske veje se opusti.
- 2026-09-18: **Vzorec workflowa `Zascita` za plačilno/dostopno logiko je ozek**:
  `requireRole|requireClub|stripe|PROVIZIJA|application_fee|QR_SECRET|preveriQr|podpisiQr|rezerviraj_zalogo|sprosti_zalogo`
  (brez `orders|tickets`). Razlog: široki vzorec je ustavil skoraj vsak PR o vstopnicah in Martin bi klikal oznako na vsakem
  backend PR-ju, kar je v nasprotju s samodejnim merge-om (16. 9.). Kar ožji vzorec spusti (npr. filtriranje `/me/orders`),
  držijo invariante I1–I10 s testi; poti `.github/workflows/**`, `CLAUDE.md`, `.claude/**`, `db/migracije/**` ostanejo pokrite.
  *vir/dokaz*: PR #29 in #30 in vsi načrtovani PR-ji (vračila, preklic, Stripe) bi se dotaknili besed `orders`/`tickets` ·
  *velja dokler*: seje tečejo na admin računu `Djurdje` (oznaka je dogovor, ne varovalo) — ob ločenem računu za agenta
  vzorec ponovno pretehtaj · *nadomeščena z*: —
- 2026-09-16 (pozneje): **Merge je samodejen.** Od Martinovega ukaza do produkcije brez njegove interakcije: agent odpre PR, počaka na zelen CI,
  PR mergaj, preveri produkcijo. Varovala so CI testi + `qa-reviewer`. Edina izjema: migracije, ki brišejo/spreminjajo produkcijske
  podatke, čakajo Martinov DA. Razlog: Martin hoče upravljati s telefona brez klikanja po GitHubu.
- 2026-09-28: **Demo klubi dobijo izmisljena imena, ne brisejo se** (Martin). Najprej je narocil brisanje vseh klubov in 5 novih,
  isti dan preklical: obstojece klube se preimenuje (Velvet = najvec dogodkov, nato Nexus, Mirage, Mansion, Olie), izpolni vse
  podatke (opis, telefon, naslov v centru LJ, zanr balkan, cenik) in dopolni dogodke do 3 koncanih + 3 prihajajocih. Narocila,
  vstopnice in obstojeci dogodki ostanejo. Migracija 022. *vir/dokaz*: pogovor 28. 9. 2026. *velja dokler*: pravi klubi ne
  podpisejo in ne vnesejo svojih podatkov. *nadomescena z*: —
- 2026-10-02: **Dnevna kopija baze izven Renderja: logični izvoz prek API-ja, šifriran z GESLOM (gpg AES-256), hranjen v ZASEBNEM Cloudflare R2 (EU); odločitev Martina v klepetu 2. 10. 2026** (issue #88).
  Workflow `Varnostna kopija baze` potegne `GET /admin/api/export` (servisni račun `agent@outly.si`), šifrira z geslom `BACKUP_GESLO` (`gpg --symmetric`, AES-256, MDC),
  naloži v R2 bucket `outly-kopije` (S3 API, endpoint `<ACCOUNT_ID>.eu.r2.cloudflarestorage.com`), prebere nazaj (sha256), **odsifrira in primerja z izvozom**, v istem zagonu preizkusi obnovo v `postgres:16`
  in po 30 dneh sam briše stare kopije (vedno pusti 7 najnovejših; R2 lifecycle pravila namenoma ni, ker bi to varovalo izničilo). Mesečno workflow `Preizkus kopije (mesecni)` kopijo iz R2 odsifrira,
  obnovi v prazno bazo in primerja (brez Martina); ob napaki rdeč zagon + push + issue. Martin je izbral R2 namesto GitHub artefakta v javnem repu: kopije so zasebne, ne le šifrirane.
  Ne `pg_dump`: zunanji dostop do `outly-db` je zaprt (30. 9.), runnerji nimajo stalnega IP-ja.
  **Sprejeto tveganje (Martin, 2. 10. 2026: preprostost):** geslo je v GitHub secrets (environment `kopije`, samo `main`), zato kdor lahko bere secrets tega okolja, lahko odsifrira kopije (prej predvideni
  zasebni ključ age samo pri Martinu je opuščen, ker Martin ročnega upravljanja ključev ne zmore). Utemeljitev: bucket je zaseben in v EU, dostop do secretov imajo samo lastnik repozitorija in workflowi na `main`
  (spremembe workflowov zahtevajo oznako `odobril-martin`), v zameno dobimo polni samodejni mesečni preizkus obnove. Nasprotni dokaz: kdor prevzame GitHub račun ali R2 in secrets hkrati, dobi kopije z osebnimi podatki.
  Servisni račun za izvoz je do preklopa obstoječi `agent@outly.si` (vloga `admin`). Vloga samo-za-izvoz `backup` je v kodi od #116 (migracija 029); preklop računa je Martinov korak (skill `obnova-baze`).
  Izhodišče števil za preverbo padca (> 20 % za users/orders/tickets) je JSON v R2 **nešifriran**: števila vrstic niso osebni podatek, bucket je zaseben, ločen ključ bi bil še en del, ki se lahko pokvari.
  Dnevniki zagonov so javni: v njih so samo imena tabel, OK/NAPAKA in odtis, nikoli števila vrstic, podatki o računu R2 ali geslo. Prag 20 % glede na prejšnji zagon **ne ujame postopnega padca** (sprejeto tveganje).
  Strošek 0 EUR do 10 GB/1 M zapisov na mesec (Cloudflare lahko ob vklopu R2 zahteva plačilno sredstvo). Rok hrambe 30 dni (in dejstvo, da šifrirani osebni podatki ležijo pri Cloudflare) v politiki zasebnosti
  ni zapisan — nepreverjeno, pregled `pravnik` pred javnim zagonom.
  *vir/dokaz*: Martinova izbira in poenostavitev v pogovoru 2. 10. 2026; STATE.md (zaprt dostop 30. 9.) · *velja dokler*: je baza zaprta za zunanje povezave in izvoz ostaja tok · *nadomeščena z*: —

## Nakup brez računa (5. 10. 2026)

- 2026-10-05: **Nakup vstopnice brez računa: kupec vpiše samo e-naslov** (Martin, 5. 10. 2026; varianto z OTP kodo iz maila je izrecno zavrnil: »spet more kodo… kot da bi account naredil«). Samo splet (`/app`), samo navadne vstopnice (VIP mize ne: alkohol 18+, prenos prijateljem).
  *vir/dokaz*: pogovor 5. 10. 2026; pravna analiza outly-hq `pravno/2026-10-05-gostujoci-nakup.md` · *velja dokler*: Martin ne odloči drugače · *nadomeščena z*: —
- 2026-10-05: **Odločitev agenta (Martin je ni potrdil): gost NI vrstica v `users`, ampak `orders.user_id = NULL` + `orders.guest_email` + žeton.** Razlogi: (1) `orders.user_id` je že nullable (po izbrisu računa) in vse poti za branje
  ga prenesejo (LEFT JOIN users), zato obstoječe poti in odgovori za prijavljene ostanejo nespremenjeni; (2) vrstica v `users` bi trčila z Supabase prijavo in povezavo po e-naslovu (isti e-naslov = tuji uid, `users_email` unique),
  gost bi se pojavil v iskanju uporabnikov, prijateljskih prošnjah in adminovem seznamu, zahteval bi izmišljeno uporabniško ime; (3) omejitev neplačanih naročil uporabnika in gostujoče omejitve se ločita same od sebe (štetje po `user_id`);
  (4) ni enumeracije računov: gostujoči nakup ne bere `users`. Cena: lastna idempotenca (vezana na e-naslov), lasten prevzem v račun, »Guest« v poslovnih pogledih. Zavrnjena alternativa: gost kot `users` z oznako brez `supabase_uid`.
- 2026-10-05: **Odločitev agenta (Martin je ni potrdil): žeton gosta** = 32 B naključja (base64url), v bazi samo sha256 (hex TEXT, ne bytea: izvoz baze je JSON), več žetonov na naročilo (največ 10; mail iz webhooka potrebuje svežega),
  v glavi `X-Guest-Token` (ne v URL-ju API zahtevka), v povezavah (`success_url`, mail) v **fragmentu `#t=`** (ne gre na Cloudflare in v Referer). Velja do konca dogodka + 30 dni in se ob prevzemu v račun prekliče (pravna analiza 2.6).
  Rok 30 dni je predlog Martinovega načrta. Gost lahko neplačano naročilo sam prekliče (`POST /guest/order/cancel`). *velja dokler*: ni drugače določeno · *nadomeščena z*: —
- 2026-10-05: **Odločitev agenta (Martin je ni potrdil): zloraba** (gost nima računa, neplačana naročila zaklepajo zalogo ~35 min): 10 nakupov/uro/IP (`GOST_NAKUP_NA_URO`), `quantity` do 6, največ 1 neplačano naročilo na (e-naslov, dogodek)
  z unikatnim delnim indeksom, skupna meja čakajočih gostujočih vstopnic na dogodek max(10, 20 % kapacitete); mail: v testnem načinu 1 na naslov na 24 h, globalno 300 na 24 h; obe meji samo za testna naročila — potrdilo plačanega naročila je zakonska obveznost in se nikoli ne odloži (ob preseženi številki samo opozorilo v dnevniku);
  neuspešni ogledi/preklici žetona 60/h/IP — veljaven žeton se obdela vedno, tudi nad mejo (skupni wifi/CGNAT: napadalec gostom na vratih ne sme onemogočiti prikaza vstopnice), nad mejo dobi 429 samo neveljaven. **Stikalo `GOST_NAKUP_LIVE=1`** (privzeto izklopljeno): gostje ne plačujejo pravega denarja (`sk_live_`), dokler Martin ne objavi pogojev/politike (sandbox in testni način delata).
  **Znana meja:** botnet z mnogimi IP-ji lahko še vedno zaseda do meje čakajočih (10–20 % kapacitete) na dogodek za ~35 min; števci po IP za ogled/iskanje so v pomnilniku procesa (ena instanca).
  **Znan kompromis (2. krog QA pregleda PR #159): (1)** napadalec z mnogimi e-naslovi lahko ~35 min zapolni mejo čakajočih gostujočih vstopnic na dogodku (max(10, 20 % kapacitete)): gostujoči nakup tega dogodka tedaj stoji (409), nakup z računom ne (meja velja samo za goste). Sprejeto, ker alternativa (brez meje) pusti napadalcu zakleniti vso zalogo.
  **(2)** Nakup 10/h/IP (`GOST_NAKUP_NA_URO`) je lahko prenizek za skupen naslov (CGNAT, wifi kluba: več deset gostov z istega IP-ja pred vrati); vrednost je nastavljiva z okoljsko spremenljivko, višino meje odloči Martin. Veljaven žeton (ogled, preklic) meje nikoli ne občuti.
- 2026-10-05: **Odločitev agenta (Martin je ni potrdil): hramba osebnih podatkov gosta** po pravni analizi 2.3: datum rojstva se NE shrani (samo `guest_age_min`); e-naslov neplačanega/preklicanega naročila se anonimizira 24 h po preklicu; plačanega
  `GOST_HRAMBA_DNI` = 180 dni po koncu dogodka (rok je PREDPOSTAVKA, Martin ga lahko spremeni; rok sporov pri kartičnih shemah ni preverjen). Mail z vstopnico je zakonsko potrdilo (ZVPot-1 132/6): celotna vsebina v besedilu; pošlje se največ enkrat ob uspehu (ob padcu procesa med pošiljanjem lahko dvakrat), z naraščajočim premorom do 24 h.
  **Ni v tej nalogi:** firma in matična številka kluba v bazi nista (`clubs` ima ime, naslov, telefon, e-naslov), zato mail kaže samo to; pogoji in politika zasebnosti (§ 3 analize) se ne spreminjajo brez Martinovega DA.

## Prenos vstopnice prijatelju brez računa (5. 10. 2026)

- 2026-10-05: **Prenos vstopnice na e-naslov prijatelja BREZ računa Outly** (Martin, 5. 10. 2026): pošiljatelj z računom vpiše samo e-naslov; prijatelj dobi mail s kodo QR (vgrajena slika), PDF in skrivno povezavo `…/app/guest/ticket#t=<žeton>`. **iOS IN splet.**
  Pošiljatelj potrdi starost prijatelja s kljukico (ni vnaprej označena). Isto (QR inline + PDF) dobi tudi mail kupca brez računa (#159). *vir/dokaz*: pogovor 5. 10. 2026; pravna presoja outly-hq `pravno/2026-10-05-prenos-brez-racuna.md` ·
  *velja dokler*: Martin ne odloči drugače · *nadomeščena z*: — (dopolnjuje odločitev o prenosu 21. 9. 2026: obstoječi prenos na račun ostaja).
- 2026-10-05: **Martinova odločitev: VIP vstopnice mize s paketom pijače se SMEJO poslati prijatelju brez računa** (kupec mize jih razdeli prijateljem; »ni naša dolžnost preverjati starost, to je dolžnost kluba«). Za gosta velja
  `max(min_age, 18)` (`starostZaPaket`) samo kot meja POTRDITVE pošiljatelja (`age_confirmed: true` je pri paketu VEDNO obvezen, brez njega 400 `age_confirmation_required` z `min_age` = ta meja), osebni dokument preveri klub na vratih.
  **To odstopa od presoje pravnika (P2, ZOPA 7/1) in od odločitve #102 (2. 10.) za goste: tveganje je sprejel Martin.** Prenos na RAČUN s paketom ostane strožji kot pri gostu: znan datum rojstva prejemnika >= meja. *vir/dokaz*: pogovor 5. 10. 2026 ·
  *velja dokler*: Martin ne odloči drugače · *nadomeščena z*: —
- 2026-10-05: **Martinova odločitev: potrditev pošiljatelja »prijatelj ima vsaj N let« velja za VSE prenose** (»naj označi, da je prijatelj 18+, in to je to«): tudi na račun in po `{ user_id }`. Pravila: (a) `age_confirmed: true` + prejemnik z računom BREZ datuma rojstva → prenos dovoljen
  (prej 403); (b) prejemnik z VPISANIM datumom rojstva pod mejo → 403 vedno (znan mladoletnik); (c) brez `age_confirmed` (stari odjemalci) → kot doslej; (d) ni vezano na stikalo `PRENOS_BREZ_RACUNA`. Meja = `min_age`, pri paketu `max(min_age, 18)`.
  Potrjena meja se hrani v `ticket_transfers.age_confirmed_min` (datuma rojstva ne). *vir/dokaz*: pogovor 5. 10. 2026 · *velja dokler*: Martin ne odloči drugače · *nadomeščena z*: —
- 2026-10-05: **Odločitev agenta (Martin je ni potrdil): stikalo `PRENOS_BREZ_RACUNA`** (pravna presoja, razdelek 4: pogoji §6 danes zahtevajo račun prejemnika, politika §2 prenosa brez računa ne opisuje). Privzeto samo vloga `admin` (ekipa testira v produkciji), `vsi` vklopi za vse;
  vklopi Martin na Renderju po objavi pogojev 1.2 in politike 2.5. `GET /me` in `PATCH /me` vračata `can_transfer_to_guest`. Stikalo velja samo za pošiljanje gostu.
- 2026-10-05: **Odločitev agenta (Martin je ni potrdil): model gostujočega imetnika** — vstopnica ostane vstopnica naročila kupca, imetnik je gost: `tickets.holder_is_guest` (loči od e-naslova, ki se anonimizira) + `holder_guest_email`; NI vrstica v `users`
  (isti razlogi kot pri gostujočem nakupu). `IMETNIK` (SQL izraz) je za gosta NULL, ne kupec. Zavrnjena alternativa: lažen `holder_user_id` (trk s Supabase prijavo, izmišljeno uporabniško ime). Serial se ob prenosu zamenja (I7); ob prevzemu v račun se NE zamenja
  (pravnik: odločitev M): PDF in koda v mailu veljata naprej, da gost, ki si dan pred dogodkom naredi račun, ne obstane pred vrati z neveljavno kodo; cena: posredovan mail ostane uporaben do vstopa (to velja tudi pred prevzemom).
- 2026-10-05: **Odločitev agenta (Martin je ni potrdil): vsebina, žeton, hramba in meje.** Mail po pravni presoji (GDPR 14 v celoti v mailu, ločen odstavek o ugovoru 21(4), varnostno besedilo, en nevtralen stavek o prevzemu v račun, brez oglasov, pošiljatelj = uporabniško ime);
  žeton 32 B (sha256 hex TEXT v `gost_zetoni_vstopnic`), kuje se šele ob pošiljanju maila (pošiljatelj ga NIKOLI ne dobi), velja do konca dogodka + 30 dni; e-naslov imetnika in `ticket_transfers.to_email` se anonimizirata ob koncu dogodka + 30 dni (pravna presoja 1.4);
  klub e-naslova gosta ne vidi nikjer (»Guest«, `is_guest_holder`), tudi lastnik ne. Meje zlorabe (mail tujemu naslovu): 10 prenosov z `allow_guest`/pošiljatelja/24 h (`GOST_PRENOS_NA_DAN`) in 10/prejemnika/24 h (`GOST_PRENOS_NA_NASLOV`, normaliziran naslov) poleg `prenos` 30/h/IP; 429 `guest_transfer_limit` (dopolnitve po QA: spodaj).
  Odgovor prenosa je za račun in gosta ENOTEN (pravna presoja P5: brez razkritja, ali ima naslov račun) — samo pri novih odjemalcih (`allow_guest: true`); stari odjemalec ohrani 404 »No Outly account«. Neizvedeno iz presoje: gumb »Zavrni vstopnico« (ugovor gre z odgovorom na mail, ročno), razveljavitev prenosa pred odprtjem (6. vprašanje odvetniku).
  Sporočilo o prenosu v ZDA (Resend) uporablja besedilo pravnika; mehanizem ni preverjen (G14).
- 2026-10-05 (po QA 1. krogu PR #161): **Odločitve agenta (Martin jih ni potrdil).** (1) Razkritje, ali ima naslov račun, je OMEJENO, ne preprečeno: pri `allow_guest` so potrditev starosti (400), meje (429) in strog e-naslov PRED iskanjem uporabnika in enaki za račun in gosta,
  meje štejejo vse prenose z `allow_guest`; stari odjemalci (brez `allow_guest`) ohranijo 404 »No Outly account« (obstoječe vedenje), nepotrjen račun z vpisanim datumom pod mejo dobi 403. (2) Prevzem gostujoče vstopnice v račun datuma rojstva NE preverja (koda je že v mailu, klub preveri osebni dokument na vratih);
  znan mladoletnik (vpisan datum pod mejo) pa pri pošiljanju dobi 403 tudi, če račun še ni potrjen. (3) Meje: `GOST_PRENOS_NA_NASLOV` na normaliziran naslov (brez `+oznake`, pike pri gmail), globalno `GOST_PRENOS_DNEVNO` (500/24 h, alarm v dnevniku), pošiljatelj `email_verified`.
  (4) Ugovor/izbris po mailu: admin pot `POST /admin/api/guest-tickets/erase` (ročno, na zahtevo prejemnika); vrnitev vstopnice pošiljatelju ni avtomatizirana. (5) Mail z več vstopnicami ima vgrajeno samo prvo kodo QR, vse so v PDF (zanesljivost: CPU na glavni niti).

## Guest lista in VIP razdelitev po nakupu (8. 10. 2026)

- 2026-10-08: **Guest lista (Martin, 8. 10. 2026):** (a) vezana na EN dogodek; nastavi jo admin v admin panelu: dogodek + uporabnik (gostitelj) + število mest (koliko prijateljev sme povabiti); (b) vsak povabljeni prijatelj dobi SVOJO QR kodo (svojo vstopnico v Tickets) in lahko pride ločen od gostitelja; gostitelj ima tudi svojo kodo;
  (c) povabi lahko SAMO prijatelje na Outlyju (`GET /me/friends`), ne po e-naslovu. *vir/dokaz*: pogovor 8. 10. 2026 · *velja dokler*: Martin ne odloči drugače · *nadomeščena z*: — (API in model: ARCHITECTURE »Guest lista«, I24).
- 2026-10-08: **VIP razdelitev po nakupu (Martin, 8. 10. 2026):** po nakupu mize kupec takoj dobi izbiro prijateljev (multi-select), lahko preskoči ali pošlje samo nekaterim, ostale vstopnice ostanejo v Tickets; ena vstopnica VEDNO ostane kupcu (pri mizi z N sedeži največ N-1 prijateljev).
  **Samo odjemalca (iOS, splet): backend se ne spreminja** (uporabi obstoječi `POST /tickets/:id/transfer { user_id, age_confirmed? }` za vsakega prijatelja, zaporedno). *vir/dokaz*: pogovor 8. 10. 2026 · *velja dokler*: Martin ne odloči drugače · *nadomeščena z*: —
- 2026-10-08: **Odločitev agenta (Martin je ni potrdil): model guest liste = posebno naročilo.** `orders.guest_list_id` (total 0, `quantity` 1, `status` stalno `paid`, brez Stripa, `user_id` = gostitelj) + navadne vrstice `tickets`; tabeli `guest_lists`, `guest_list_members` (migracija 035).
  Razlog: skener, sken brez povezave (`scan-list`), `GET /me/tickets`, QR (I6) in pogojni `UPDATE` pri skenu (I1) delujejo brez podvajanja in brez sprememb na odjemalcu (kot VIP vstopnice in prenos, ki tudi sta vstopnici naročila). Zavrnjena alternativa: lastna tabela vstopnic guest liste (skener, scan-list, I1/I7 in `/me/tickets` bi morali delati na dveh tabelah; več poti, kjer bi lahko ena pozabila drugo).
  Cena modela: vsaka agregacija nad `orders` mora izločiti `guest_list_id IS NOT NULL` (I24; test po vsaki agregaciji, CHECK `orders_guest_lista_chk` pa v bazi prepreči, da bi naročilo guest liste kdaj dobilo znesek, Stripe ali vračilo).
- 2026-10-08: **Odločitev agenta (Martin je ni potrdil): guest lista NE šteje v kapaciteto in prodajo.** Sprožilca `rezerviraj_zalogo`/`sprosti_zalogo` naročilo preskočita (kot VIP mize); ne v `sold_count`, `tickets_sold`, bruto, število naročil, `GET /me/orders`. Posledica: gostitelj + do 20 povabljenih lahko skupaj z prodajo preseže `capacity` dogodka; odgovornost za velikost liste je pri adminu (mest je največ 20 na listo).
  Zavrnjena alternativa: šteti v kapaciteto (guest lista bi pri skoraj razprodanem dogodku izpodrinila plačnike, `sold_count` bi pomenil dvoje). `checked_in` v prodaji šteje vse vstope vključno z guest listo (prihod na vrata, ne prodaja).
- 2026-10-08: **Odločitev agenta (Martin je ni potrdil): podrobnosti guest liste.** (1) Gostiteljeva vstopnica nastane ob ustvarjanju liste (admin ne čaka na gostitelja), `holder_user_id` izrecen (ne »kupec«). (2) Odstranitev in preklic = `void`, nikoli brisanje; uporabljene vstopnice se ne razveljavijo (409 / ostane `used`). (3) Lista samo za objavljen dogodek, ki se ni končal; ena aktivna lista na (dogodek, gostitelj), po preklicu je nova mogoča.
  (4) Starost: ista pravila kot prenos (znan datum pod mejo: 403 vedno, brez datuma: `age_confirmed`); ena potrditev velja za vse izbrane v zahtevku. (5) Vstopnice guest liste se ne prenašajo (409): prenos bi obšel preverbo prijateljstva in starosti pri vabilu. (6) E-naslovov gostitelja in povabljenih klub ne vidi nikjer (tudi lastnik ne): za vrata zadoščata uporabniško ime in »Guest list · @host«.
  (7) Zloraba: omejevalnik 30/h/IP za vabilo/odstranitev in meja 60 vrstic povabljencev na listi (tudi odstranjenih; `GUEST_LISTA_VRSTIC_NAJVEC`). (8) Izbris računa gostitelja prekliče njegove liste, izbris povabljenca razveljavi njegovo vstopnico in sprosti mesto (sicer bi vstopnica zdrsnila na gostitelja). (9) Prijatelj ob vabilu NE dobi obvestila (ne push, ne `/me/tickets/received`): vstopnico vidi, ko odpre Tickets;
  obvestilo prek `ticket_transfers` je zavrnjeno, ker bi pokvarilo `transferred_serials` v scan-list (I7). (10) Brez stikala za vklop: ustvarjanje je samo admin, zato je funkcija izklopljena, dokler admin ne ustvari liste.
