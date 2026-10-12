---
name: preverjanje-produkcije
description: Preverjanje produkcije po merge-u v main (Render deploy backenda, Cloudflare Pages za outly.si, TestFlight za iOS) iz oblacne seje: Render MCP, GitHub Actions in (kadar ga mreza okolja dovoli) neposreden curl na produkcijo. Uporabi po vsakem merge-u, ki gre v produkcijo, in ko sumis izpad.
---
# Preverjanje produkcije po deployu

**Dostop je odvisen od mreznih nastavitev okolja — vedno ga najprej izmeri, ne predpostavljaj.** 1.-2. 10. 2026 so seje
za `onrender.com`, `outly.si`, `supabase.co` in `ntfy.sh` dobile 403; **12. 10. 2026 so bili vsi dosegljivi** (200; `/me/invites`
401, kot mora biti). Zastarela trditev »ni izhoda« je 12. 10. povzrocila, da je agent Martinu po nepotrebnem nalozil rocni preizkus.

```bash
for u in https://outly-backend-roy3.onrender.com/clubs https://outly-backend-roy3.onrender.com/events \
         https://outly-backend-roy3.onrender.com/me/invites https://outly.si https://outly.si/app/; do
  echo "$(curl -sS -o /dev/null -m 20 -w '%{http_code}' "$u")  $u"; done
# pricakovano: 200 200 401 200 200; 403/000 od proxyja = ni izhoda -> samo Render MCP + Nadzor (spodaj)
```
Ce je izhod: neposreden curl je **dodatna** preverba (hitra, takoj po deployu); Render MCP (deploy na pravem commitu, 5xx)
in Nadzor ostaneta obvezna, ker curl ne pove, kateri commit tece. Splet (/app) lahko odpres v headless Chromiumu na zivi
strani (skill `headless-preverjanje-strani`), a NIKOLI ne oddajaj obrazcev, ki posljejo mail ali spremenijo podatke.
Supabase RPC z javnim kljucem (`supabase-config.js`) preverjaj samo z vhodi brez stranskih ucinkov (npr. `join_waitlist`
z neveljavnim naslovom -> `"invalid"`, odvzeta funkcija -> 401 `42501`). Postopek odkrit 1.-2. 10. 2026, dopolnjen 12. 10.
(vir: `outly-hq/docs/UCENJE.md`, `docs/INCIDENTI.md` 12. 10.).

## Backend (Render, ~30-90 s po merge-u)

1. **Deploy je live na pravem commitu** — Render MCP (`ToolSearch` → `mcp__Render__list_deploys`):
   `serviceId: srv-d5fuiovgi27c73e4boq0`, `workspaceId: tea-d5ftup1r0fns73c3l510`, `limit: 1`.
   Pricakuj `commit.id` = merge SHA in `status: live`. `build_in_progress` / `update_in_progress` → pocakaj
   (`Bash` `sleep 60` z `run_in_background`, ne zanka v ospredju) in ponovi. `build_failed` / `update_failed` → takoj
   `list_logs` (`type: ["build"]` ali `["app"]`) in popravek ali revert PR.
2. **Migracija** (ce je PR imel novo `db/migracije/NNN_*.sql`) — `mcp__Render__list_logs`, `resource:
   ["srv-d5fuiovgi27c73e4boq0"]`, `text: ["*NNN*"]`, `startTime` = cas merge-a. Pricakuj `→ NNN_ime.sql ... v redu (x ms)`.
3. **5xx po deployu** — `list_logs` z `statusCode: ["5*"]`, `startTime` = cas `finishedAt` deploya. Pricakuj prazno.
4. **Nadzor produkcije** — sele **ko je deploy live** (2. 10. je tekel 5 s pred preklopom in preveril staro razlicico):
   `mcp__github__actions_run_trigger` `run_workflow`, `workflow_id: nadzor.yml`, `ref: main`, `inputs: {"test":"false"}`;
   cez ~30 s `actions_list` `list_workflow_runs` (`resource_id: nadzor.yml`, `workflow_runs_filter: {"event":"workflow_dispatch"}`,
   `perPage: 1`) → `conclusion: success` in `head_sha` = merge SHA. Preveri `/clubs` 200, `/events` 200, `/admin/` 200,
   `/me/invites` 401, `outly.si` 200, `/terms` 200, Supabase health 200.
   `test: "true"` ali `"routine"` posljeta testno obvestilo / testno sprozita Popravljalca — za preverjanje deploya NE.

## Splet (Cloudflare Pages, ~1 min, CDN do 10 min)

Nadzor produkcije (zgoraj) preveri `outly.si` in `/terms`. Za spremenjene strani `/app`: nova razlicica se ne vidi iz
seje; v porocilo napisi, kaj naj Martin odpre na telefonu. Ce je kaj narobe: takoj revert PR + merge.

## iOS (TestFlight, ~8-10 min)

`actions_list` `list_workflow_runs` v `outly-app`, `workflow_runs_filter: {"branch":"master","event":"push"}`,
`perPage: 1` → `head_sha` = merge SHA, `conclusion: success`. Rdec master = TestFlight brez gradnje: takoj diagnoza
(`get_job_logs` z `return_content: true`, `tail_lines: 120`), popravek PR.

## Zapis

Vsaka seja, ki se je dotaknila produkcije, doda vrstico v `docs/INCIDENTI.md` (tudi »brez alarma«: cas, PR-ji,
migracija in trajanje, Nadzor zelen) — v naslednjem PR-ju ali v svojem majhnem docs PR-ju.
