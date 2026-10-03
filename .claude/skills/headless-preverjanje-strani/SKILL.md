---
name: headless-preverjanje-strani
description: Headless preverjanje outly.si (landing in spletna aplikacija /app) v oblacni seji brez izhodnega dostopa - Playwright z Chromiumom iz /opt/pw-browsers, stub samo *.supabase.co in backenda, konzola brez napak, mobilna sirina 393 px, posnetki zaslona.
---

# Headless preverjanje strani (outly.si)

**Kdaj:** pred vsakim PR-jem v `outly_webpage` (CLAUDE.md spletne strani, pravilo 8) in kadar je treba
preveriti, kako se razdelek izrise na telefonu (iPhone 14 Pro, 393 px) in namizju.

**Kaj je dosegljivo:** v oblacni seji `outly.si`, `onrender.com` in `supabase.co` niso dosegljivi (egress proxy).
Stran sama ne nalaga nobenega tujega vira: supabase-js je v `vendor/supabase-2.115.0.js`, Inter v `assets/fonts/`
(preverjeno 2. 10. 2026: `grep -rn "jsdelivr\|googleapis\|gstatic"` po `*.html`, `app/`, `webapp/` ne najde nic).
Stubati je treba samo **`*.supabase.co`** (REST/RPC/Auth) in backend (`onrender.com`).

## Koraki

1. Playwright brez prenosa brskalnika; **nikoli `playwright install`** (brez dostopa, brskalnik je ze v `/opt/pw-browsers`):
   ```bash
   mkdir -p "$SCRATCH/pw" && cd "$SCRATCH/pw" && npm init -y >/dev/null
   PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm i playwright@latest --no-audit --no-fund
   ls -d /opt/pw-browsers/chromium-*/chrome-linux/chrome   # to pot daj v executablePath
   ```
2. Staticni streznik iz mape spletne strani (za `/app` globoke povezave glej CLAUDE.md: streznik mora posnemati
   `_redirects`/`_headers` in neznano pot vrniti z korenskim `index.html`):
   ```bash
   (cd /home/user/outly_webpage && python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 &)
   ```
3. Kopiraj `preveri_stran.js` iz te mape v `$SCRATCH/pw/`, po potrebi popravi `executablePath`, nato
   `cd "$SCRATCH/pw" && node preveri_stran.js /index.html '#features'` (pot, selektor za posnetek). Skript stuba samo `supabase` (-> `[]`) in `onrender` (-> 401),
   belezi `console.error` in `pageerror`, meri vodoravni overflow, naredi posnetke za 393x852 in 1280x900.
4. Posnetke v `shots/` **poglej** (Read), ne samo preberi "OK": centriranje, prelomi, prekrivanja.
5. V opis PR-ja napisi: kaj je bilo stubano, konzola brez napak, brez overflowa, kateri posnetki pregledani.
   Po objavi (Cloudflare ~1 min) stran preveri Martin v brskalniku - iz oblaka ni dosegljiva.

## Pasti

- **`page.route` izklopi HTTP predpomnilnik** brskalnika. Zato z njim ne preverjaj predpomnjenja, zagona po objavi
  (`zagon.js`) ali service workerja; take teste delaj brez `page.route` (npr. stub na lokalnem streznikku).
- supabase-js odpre **WebSocket** (Realtime) na `wss://*.supabase.co`; `page.route` ga ne zajame, zato konzola javi
  `ERR_CERT_AUTHORITY_INVALID`. Stubaj ga s `page.routeWebSocket(/supabase\.co/, () => {})` (kot v `preveri_stran.js`).
- `playwright@1.5` je starodavna razlicica (brez `page.locator`); vedno `@latest` ali `@1.5x`.
- Stub `*.supabase.co` mora vrniti veljavno obliko (`[]` za REST); `auth.js` in `webapp/js/seja.js` brez seje tiho
  izpustita plosco/prijavo, zato "plosca se ni odprla" pomeni napacen stub ali selektor, ne nujno hrosc.
- `.drawer` je `#authDrawer`; odprt = `!hidden && classList.contains("is-open")` (odpre se po dveh
  `requestAnimationFrame`, pocakaj ~500 ms). Selektorje preberi iz trenutnega HTML-ja, ne iz spomina.
- `backdrop-filter` + Web Share je na iOS Safari ze podrl stran (commit 87bc106) - headless test tega ne ujame.
