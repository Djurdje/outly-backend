---
name: headless-preverjanje-strani
description: Headless preverjanje outly.si (ali druge staticne strani) v oblacni seji brez izhodnega dostopa - stub Supabase REST in supabase-js CDN, konzola brez napak, mobilna sirina 393 px, posnetki zaslona.
---

# Headless preverjanje strani (outly.si)

**Kdaj:** pred vsakim PR-jem v `outly_webpage` (CLAUDE.md spletne strani, pravilo 8) in kadar je treba
preveriti, kako se razdelek izrise na telefonu (iPhone 14 Pro, 393 px) in namizju.

**Zakaj skill:** v oblacni seji `download.swift.org`, `outly.si`, `onrender.com`, `supabase.co` in
`cdn.jsdelivr.net` niso dosegljivi (egress proxy). Brez stuba CDN skripta `window.supabase` ne obstaja,
`auth.js` tiho izpusti plosco in test napacno javi "plosca se ni odprla". To je bilo odkrito dvakrat
(prejsnje seje: `recovery_test.js`, ki ni v repu; 20. 9. 2026: razdelek Points).

## Koraki

1. Playwright brez prenosa brskalnika (Chromium je ze v `/opt/pw-browsers`):
   ```bash
   mkdir -p "$SCRATCH/pw" && cd "$SCRATCH/pw" && npm init -y >/dev/null
   PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm i playwright@latest --no-audit --no-fund
   ls /opt/pw-browsers            # npr. chromium-1194 -> executablePath spodaj
   ```
2. Staticni streznik iz mape spletne strani:
   ```bash
   (cd /home/user/outly_webpage && python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 &)
   ```
3. Kopiraj `preveri_stran.js` iz te mape v `$SCRATCH/pw/`, prilagodi selektorje (`#points`,
   `#pointsInviteBtn` ...) in `executablePath`, nato:
   ```bash
   cd "$SCRATCH/pw" && node preveri_stran.js
   ```
   Skript: stuba vse, kar ni `127.0.0.1` (supabase-js UMD -> minimalen `window.supabase` z `auth.getSession`,
   `onAuthStateChange`, `rpc`, verizni `from()`; Supabase REST -> `[]`; backend -> 401; fonti -> prazen CSS),
   belezi `console.error` in `pageerror`, meri vodoravni overflow, naredi posnetke razdelka in plosce
   za 393x852 (mobile) in 1280x900.
4. Posnetke v `shots/` **poglej** (Read), ne samo preberi "OK": centriranje, prelomi, prekrivanja.
5. V opis PR-ja napisi: kaj je bilo stubano, konzola brez napak, brez overflowa, kateri posnetki pregledani.
   Po objavi (Cloudflare ~1 min) stran preveri Martin v brskalniku - iz oblaka ni dosegljiva.

## Pasti

- `playwright@1.5` je starodavna razlicica (brez `page.locator`); vedno `@latest` ali `@1.5x`.
- `.drawer` je `#authDrawer`; odprt = `!hidden && classList.contains("is-open")` (odpre se po dveh
  `requestAnimationFrame`, pocakaj ~500 ms).
- Razred `.points` je kartica tock v profilu, ne razdelek na strani.
- `backdrop-filter` + Web Share je na iOS Safari ze podrl stran (commit 87bc106) - headless test tega ne ujame.
