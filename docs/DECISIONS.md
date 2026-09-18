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
- 2026-09-11: Ekipa kluba: lastnik (`clubs.owner_user_id`) + člani `manager | doorman` (`club_members`); uporabnik je v največ
  eni ekipi; vratar sme samo skenirati in gledati vstopnice dogodka. Član nastane šele ob sprejemu vabila (`club_invites`, 013).
- 2026-09: **En klub na poslovni račun.** *velja dokler*: nihče od strank ne vodi dveh lokalov
  (`klubUporabnika()` vzame prvi klub — veriga lokalov to odločitev odpre).
- 2026-09-08: **Admin panel je spletna stran v `outly-backend/admin/`**, preprosta, v slogu konzole, brez Figme. Prvi admin je Martin.
- 2026-09-08: Servisni admin račun `agent@outly.si` za agentova dejanja v produkciji (geslo ima Martin; nikoli v datotekah).
  *velja dokler*: agent res potrebuje admin pravice v produkciji — ko jih ne, se račun degradira (naloga v Issues).

## Produkti in vsebina

- 2026-09-09/10: **Povabilo prijateljev**: brez nagrad; 1 točka na vabilo, šteje šele ob potrditvi maila povabljenega;
  invite link samo za registrirane uporabnike (nadomešča odločitev z 9. 9., ko je bil link tudi na confirm.html).
- 2026-09-10: Registrirani se v javni waitlisti kažejo z delno zakritim imenom + »created a profile«.
- 2026-09-10: Zavihek Saved umaknjen; **Liked events** je razdelek na domačem zaslonu (nav bar: Home, Search, Map, Profile).
- 2026-09-14: Gumb **Bar prices** na zaslonu dogodka odpre cenik, ki ga klub sam ureja v aplikaciji (`clubs.bar_prices` JSONB, 014).
- 2026-09-14/15: Stran kluba: slideshow do 3 slik + video kluba (`gallery_urls`, `video_url`, 015); zaslon dogodka po Lukovih navodilih
  (plakat dogodka čez vrh, naslov pod pasico, gumb za nakup prosojen na pasici).
- 2026-09: Slike klubov v produkciji so ZA DEMO (prave s spletnih strani klubov). Pred pravim zagonom jih zamenjajo slike,
  ki jih dajo klubi (dovoljenje!).
- 2026-09: **Testni način plačil**: dokler `STRIPE_SECRET_KEY` ni nastavljen, je naročilo takoj `paid` z oznako `test_`;
  aplikacija to jasno kaže. Ob nastavitvi ključa testna pot vrne 503.
  *velja dokler*: `STRIPE_SECRET_KEY` ni nastavljen na Renderju — takrat se ta pot izklopi sama, brez spremembe kode.

## Oblikovanje

- Figma datoteka `XeVmPgY0LDGkNcQGBkNDbg` (stran »App«, ~147 zaslonov 393×852) je merodajna za postavitev,
  a ne 1:1: temna tema, modra `#4C76FF` samo na glavnem gumbu (ne na velikih ploskvah), »prijazno za oči«,
  brez vijolično-modrih prelivov, brez emojijev kot ikon, ena poudarjena stvar na zaslon, 8-pt mreža, SF Symbols.
- Vsaka kartica mora nekam voditi. Slike vedno `Color.clear.overlay(img.resizable().scaledToFill()).clipped()`.

## Infrastruktura (odločeno 14. 9. 2026 po sestanku z investitorji)

- Render web service → paket 7 USD (0,5 CPU, 512 MB) je dovolj za 500+ uporabnikov.
  *vir/dokaz*: stresni test 11. 9. 2026 — 616 req/s pri 40 vzporednih, brez napak.
  *velja dokler*: teče **ena instanca** backenda; ob drugi instanci padeta omejevalnik poskusov v pomnilniku (S-02)
  in ta izračun zmogljivosti.
- Render baza → plačljivi paket **pred 7. 10. 2026** (brezplačna se izbriše; januarja se je to že zgodilo).
  *velja dokler*: 7. 10. 2026 — po tem datumu ni več odločitev, ampak izgubljena baza.
- 2026-09-16: Apple Developer: Martin ima **Individual račun**; pozneje App Transfer na NEXT DIMENSIONS. Bundle ID `si.outly.app`,
  ime v App Store Connect »Outly - Nightlife« (»Outly« zasedeno). **Distribucija samo prek TestFlighta** (podpis v GitHub Actions s cloud
  signing, API ključ v secrets, nič v repu); Sideloadly/AltServer se opustita. Runner `macos-26`; `MARKETING_VERSION` dviguje Martin.
  *velja dokler*: je račun **Individual** (App Transfer na NEXT DIMENSIONS zahteva nove ključe v secrets in nov dogovor o vlogah)
  in dokler Apple sprejema iOS 26 SDK (`macos-26`).
- 2026-09-16: iOS PR-ji morajo skozi prevod za simulator v Actions pred merge-om; TestFlight upload samo ob pushu v `master`.
- Stripe račun odpre Luka za NEXT DIMENSIONS; Connect Express za klube; ključi `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET`
  na Render nastavi Martin/Luka; webhook `/stripe/webhook`, idempotentnost prek `orders_pi_key`.
  *velja dokler*: je Outly posrednik in ne prodajalec (destination charges).
- Supabase Pro (25 USD) pred javnim zagonom (kopije). *velja dokler*: brezplačni paket zadošča —
  torej do javnega zagona oziroma do trenutka, ko je izguba prijav nesprejemljiva.
- Spletna stran: Cloudflare Pages (od 10. 9. 2026), ne GitHub Pages (komercialna raba ni dovoljena).
  *vir/dokaz*: pogoji uporabe GitHub Pages (prepoved komercialne rabe). *velja dokler*: stran nima builda in
  je vse v repu javno (zato v repu nič internega).

## Način dela (odločeno 16. 9. 2026)

- Vsi trije repozitoriji imajo `CLAUDE.md` + `.claude/agents/`; ta datoteka in `STATE.md` (v backend repu) sta skupni
  možgani vseh agentov. Delo teče prek **cloud sej Claude Code** (claude.ai/code, mobilna aplikacija) in PR-jev;
  `main`/`master` sta zaščitena, merge šele po zelenem CI. Neposredno potiskanje v produkcijske veje se opusti.
- 2026-09-16 (pozneje): **Merge je samodejen.** Od Martinovega ukaza do produkcije brez njegove interakcije: agent odpre PR, počaka na zelen CI,
  PR mergaj, preveri produkcijo. Varovala so CI testi + `qa-reviewer`. Edina izjema: migracije, ki brišejo/spreminjajo produkcijske
  podatke, čakajo Martinov DA. Razlog: Martin hoče upravljati s telefona brez klikanja po GitHubu.
