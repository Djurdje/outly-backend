---
name: preverjanje-produkcije
description: Preverjanje produkcije po merge-u v main (Render deploy backenda, Cloudflare Pages za outly.si, TestFlight za iOS) iz oblacne seje, ki do onrender.com, outly.si in supabase.co nima izhoda. Uporabi po vsakem merge-u, ki gre v produkcijo, in ko sumis izpad.
---
# Preverjanje produkcije po deployu

Oblacne seje dobijo 403 za `onrender.com`, `outly.si`, `supabase.co` in `ntfy.sh` — produkcije ne gledas s `curl`,
ampak prek Render MCP in GitHub Actions. Postopek odkrit 1.-2. 10. 2026 (vir: `outly-hq/docs/UCENJE.md`).

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
