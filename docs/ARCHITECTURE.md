# Arhitektura — kje kaj je

Outly = aplikacija za nočno življenje (»kam iti nocoj«): klubi, dogodki, vstopnice. Podjetje NEXT DIMENSIONS d.o.o.
Ljudje: Martin (lastnik projekta, Render in Apple račun, Windows, brez Maca), Luka Rakuša Đurđević (GitHub `Djurdje`,
Resend/Cloudflare/Brevo račun `lukenzi553@gmail.com`, ima Mac), Fedja.

## Repozitoriji (GitHub)

| Repo | Kaj | Veja | Deploy |
|---|---|---|---|
| `Djurdje/outly-backend` (javen) | Express API + admin panel + migracije | `main` | Render auto-deploy, ~60 s; `npm run migrate && npm start` |
| `Djurdje/outly-app` (zaseben) | iOS aplikacija, SwiftUI, Xcode 16 format (sinhronizirana mapa) | `master` | GitHub Actions `Gradnja iOS` (macOS runner) → nepodpisan IPA + simulatorski build |
| `Djurdje/outly_webpage` (javen) | Spletna stran outly.si: landing, waitlist, profil, Creator, pravni dokumenti | `main` | Cloudflare Pages, projekt `outly-webpage`, brez builda; vsak merge je živ |

Stara/neaktivna: `slon3studio/outly-ios`, `Djurdje/Outly` — ne uporabljaj.

## Produkcija

- **Backend**: `https://outly-backend-roy3.onrender.com` (Render, Martinov račun »My Workspace«),
  storitev `srv-d5fuiovgi27c73e4boq0`; admin panel `/admin/`.
- **Baza**: Render PostgreSQL 16 `outly-db` (`dpg-daf7vav40ujc73a28g8g-a`, Frankfurt). Dosegljiva samo z Renderja
  (`DATABASE_URL` v okolju storitve). Izvoz: `GET /admin/api/export` (gumb v admin panelu).
- **Identiteta**: Supabase Auth, projekt `zbewqcxnvrwebxonvebx` (skupen za aplikacijo in spletno stran).
  Supabase hrani tudi waitlist spletne strani (tabele `waitlist_signups`, `waitlist_public`, `creator_applications`, RPC-ji, pg_cron).
- **E-pošta**: aplikacija/backend → **Resend** (`noreply@outly.si`, domena verificirana, brezplačno 3.000/mesec);
  spletna stran/waitlist in Supabase Auth maili → **Brevo** SMTP (`luka@outly.si`). Dva ločena ponudnika, namenoma.
- **Slike/video**: Cloudinary (podpis prek `/uploads/cloudinary-signature`).
- **Domena**: `outly.si` pri Domenci, DNS na Cloudflare; pošta na Domenca MAX M (do 1. 5. 2027).
- **Plačila**: še testni način (brez denarja). Stripe pride (glej DECISIONS.md).

## Tok podatkov

```
iPhone (SwiftUI) ──Supabase JWT──▶ Express (Render) ──▶ PostgreSQL (Render)
        │                              │
        └─ prijava/registracija ──▶ Supabase Auth (GoTrue REST)     Resend (maili), Cloudinary (mediji)

outly.si (statika, Cloudflare Pages) ──▶ Supabase (Auth + waitlist RPC)
                                     └──▶ Express /me, /creator-applications (isti žeton kot aplikacija)
```

## iOS brez Maca — kako pride gradnja na telefon

1. Commit + push na `master` → Actions `Gradnja iOS` (~3 min) → artefakt `Outly-nepodpisan.ipa` in `Outly-simulator-app`.
2. Do TestFlighta: Sideloadly (USB, 7 dni; Anisette Remote) ali appetize.io (simulator v brskalniku), ali Luka z Xcodom.
3. Cilj: App Store Connect API ključ kot GitHub secrets → podpisana gradnja → TestFlight (Apple Developer račun obstaja od 16. 9. 2026).

Pred vsakim potiskom iOS kode: `swiftc -parse` na spremenjenih datotekah + neodvisen pregled tipov; »dela« pomeni zelen Actions.

## Oblikovanje

Figma `XeVmPgY0LDGkNcQGBkNDbg`, stran »App« (id `0:1`). Figma MCP ima dnevno omejitev (Starter) — ogled gre tudi prek
figma.com v brskalniku (`node-id` v URL). Strani »Admin panel« v Figmi ni (admin je namenoma preprost).

## Orodja za ročno preverjanje (mapa `outly/` na Martinovem računalniku, niso v repih)

`outly-konzola.html` (klici na backend v živo), `outly-qr-vstopnice.html` (QR za test skenerja),
`outly-plakati.html` (zamenjava plakata), `backup/` (izvozi baze), `pravno/` (osnutki z opombami).
