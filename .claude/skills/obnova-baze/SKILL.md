---
name: obnova-baze
description: Varnostna kopija produkcijske baze outly-db izven Renderja (dnevni izvoz, šifriran z geslom BACKUP_GESLO, v zasebnem Cloudflare R2) in postopek obnove. Uporabi, ko je baza izgubljena ali pokvarjena, ko je treba preizkusiti obnovo kopije, ali ko se spreminja nastavitev kopij (geslo, R2, secrets).
---

# Obnova baze `outly-db` iz varnostne kopije

Issue #88. **Obnova v PRODUKCIJO samo z Martinovim DA.** Agent nikoli ne sprejme in ne zapiše `DATABASE_URL` ali gesel: ukaze s temi vrednostmi poganja
Martin v svojem terminalu, agent mu jih pripravi. Geslo za kopije (`BACKUP_GESLO`) agent nikoli ne vidi; odsifrira ga samo workflow v GitHubu.

## Kako kopija nastane (da veš, kaj imaš)

- Workflow `Varnostna kopija baze` (`.github/workflows/kopija.yml`) teče vsak dan ob 06:23 UTC (08:23 poleti / 07:23 pozimi; GitHub cron zna zamuditi) in ročno.
  Job teče v GitHub environmentu `kopije`, ki je omejen na vejo `main`.
- Prek `GET /admin/api/export` (servisni račun `agent@outly.si`, vloga `admin`, prijava s Supabase geslom) potegne **logični izvoz vseh tabel** kot JSON — isti izvoz in ista obnova
  (`db/obnovi_izvoz.js`) kot v `ARCHITECTURE.md`, razdelek »Varnostne kopije in obnova«. **Ni `pg_dump`**: zunanji dostop do `outly-db` je
  zaprt (STATE.md, 30. 9. 2026), GitHubovi runnerji pa nimajo stalnega IP-ja; z API-jem baza ostane zaprta. Izvoz namenoma izpusti tabelo `omejitve` (števci omejevalnika).
- Izvoz se stisne (gzip) in **šifrira z geslom** (`gpg --symmetric`, AES-256, S2K SHA-512 z velikim številom ponovitev, paket z MDC = zaščita pred spremembo; `_orodja/kopija/sifriraj.sh`).
  Geslo je `BACKUP_GESLO` (environment secret), gre v gpg prek deskriptorja (ne ukazna vrstica, ne izpis). Šifrirana datoteka se naloži v **zasebni Cloudflare R2 bucket**
  (EU jurisdikcija, S3 API prek `aws` CLI, `_orodja/kopija/r2.sh`), **prebere nazaj** (sha256) in **odsifrira: vsebina mora biti bajt za bajtom enaka izvozu** (vsak dan dokaz, da geslo odpre kopijo).
  Ključi: `kopije/YYYY/MM/outly-db-YYYY-MM-DD-r<run_id>-<poskus>.json.gz.gpg` in `….sha256`. **Nič ni v GitHub artefaktih** (repo je javen).
- **Sprejeto tveganje (DECISIONS 2. 10. 2026):** geslo je v GitHub secrets, zato kdor lahko bere secrets okolja `kopije` (lastnik repozitorija, workflow na `main`), lahko odsifrira kopije.
  Varovala: environment samo za `main`, bucket zaseben (EU), PR s spremembo workflowov zahteva oznako `odobril-martin`. Zato je mogoč polni samodejni preizkus obnove.
- **Hramba 30 dni:** workflow sam pobriše kopije, starejše od 30 dni (`cisti_stare.sh`; vedno pusti najnovejših 7, ne dotakne se `kopije/stanje/`; če se najnovejša kopija
  od današnjega časa razlikuje za več kot 2 dni, ne briše ničesar). **R2 lifecycle pravila NE nastavljaj:** briše po času, ne glede na to, koliko kopij ostane, in bi izničilo
  varovalo »vedno 7 najnovejših« (če bi kopije prenehale nastajati, bi po 35 dneh izginile vse).
- **Nič se ne prepiše:** ključ vsebuje `run_id` in številko poskusa, zato cron in ročni zagon istega dne dasta dve kopiji; če bi ključ že obstajal, zagon pade.
- **Isti zagon takoj preizkusi obnovo** (pred šifriranjem): migracije v `postgres:16` → `db/obnovi_izvoz.js` → neodvisna primerjava števil vrstic po
  tabelah in seznama migracij (`_orodja/kopija/stevila.js`). Preverba popolnosti: **vsaka tabela migrirane sheme mora biti v izvozu** (tudi z 0 vrsticami; izjema `omejitve`),
  sicer je zagon rdeč.
- **Preverba padca:** če število vrstic `users`, `orders` ali `tickets` pade za > 20 % glede na prejšnji zagon, je zagon rdeč (kopija je vseeno shranjena);
  namerno čiščenje potrdiš z ročnim zagonom `potrdi_padec = true`. Izhodišče je JSON s tremi števili v R2 (`kopije/stanje/stevila.json`), **nešifrirano** (števila vrstic niso osebni podatek,
  bucket je zaseben; nov ključ bi bila le še ena stvar, ki se lahko pokvari). Brez izhodišča (prvi zagon, izbrisan ali pokvarjen objekt) je opozorilo in vrstica v povzetku;
  če ga ni 2 zagona zapored (oznaka `kopije/stanje/brez-izhodisca`), je zagon rdeč.
  Prag 20 % glede na prejšnji dan **ne ujame postopnega padca** (sprejeto tveganje). V javnem dnevniku in povzetku so samo imena tabel in OK/NAPAKA — števila vrstic so poslovna informacija.
- Ob napaki ali prekinitvi: rdeč zagon (mail) + push na ntfy (`NTFY_TOPIC`), ki našteje vse razloge. Healthchecks (`HC_URL_KOPIJE`, neobvezen) javi, če kopija sploh ne steče.
- **Mesečno** (`Preizkus kopije (mesecni)`, 1. v mesecu, brez Martina): vzame kopijo, kot leži v R2, preveri svežino (≤ 50 h) in sha256, jo **odsifrira z BACKUP_GESLO,
  obnovi v prazno bazo (service container `postgres:16`) in primerja tabele in migracije**. Ob napaki: rdeč zagon + push + issue (oznaka `agent`).

**Česa kopija NE vsebuje:** Supabase Auth (gesla/prijave so v Supabase; v bazi je samo `users.supabase_uid`) — zanj velja Supabaseov paket;
Cloudinary slike; Stripe; nastavitve Rendera. Časovni žigi so v izvozu zaokroženi na milisekundo (JS `Date`), kar ne vpliva na delovanje.

## Nastavitev (stanje 2. 10. 2026)

Že narejeno: environment `kopije` (samo `main`), secrets `R2_ACCOUNT_ID`, `R2_BUCKET` (= `outly-kopije`, jurisdikcija EU, javni dostop izklopljen), `BACKUP_ADMIN_EMAIL` (= `agent@outly.si`).
**Preostane Martinu (4 secreti v environment `kopije`; ne v chat, ne v mail):**

1. **`R2_ACCESS_KEY_ID` in `R2_SECRET_ACCESS_KEY`:** Cloudflare → R2 → *Manage API tokens* → *Create Account API token* (ali *User API token*): dovoljenje **Object Read & Write**,
   *Apply to specific buckets only* → `outly-kopije`, brez poteka ali 1 leto (ob poteku koledarski opomnik). Izpiše *Access Key ID* in *Secret Access Key* (drugi se pokaže samo enkrat).
   Token sme brisati (workflow čisti stare kopije); omejen je na ta bucket.
2. **`BACKUP_ADMIN_PASSWORD`:** trenutno Supabase geslo računa `agent@outly.si`. Ob menjavi gesla tega računa posodobi tudi secret (sicer prijava za izvoz pade z `HTTP 400`).
3. **`BACKUP_GESLO`:** novo dolgo geslo, ustvarjeno v upravljalniku gesel (**vsaj 32 znakov, samo črke in številke**, brez nove vrstice), vpiši ga v secret **in ga shrani tudi v upravljalnik gesel**.
   **Brez tega gesla kopij ni mogoče odpreti** (tudi če izgubiš GitHub dostop). Menjava gesla: glej »Menjava gesla«.

Nato: Actions → *Varnostna kopija baze* → *Run workflow* (veja `main`). Zelen zagon = v R2 `kopije/YYYY/MM/` je kopija, v povzetku »naloženo in preverjeno nazaj« in OK/NAPAKA po tabelah.
Prvi zagon ima vedno opozorilo »izhodišče ni« (pričakovano). Za preizkus alarma isti workflow z `test` = `true` (pošlje samo testni push).
Isti dan zaženi tudi *Preizkus kopije (mesecni)* (polni preizkus obnove). Zunanjega dostopa do baze **ne odpiraj** (Render → Inbound IP Rules ostanejo prazna); kopija ga ne rabi.

**Pozneje, neobvezno:** Healthchecks.io — nov check »Outly kopija«, **Period 1 day, Grace 24 hours**, obvestilo na isti ntfy kanal; ping URL → environment secret `HC_URL_KOPIJE`.
Brez njega kopija, ki sploh ne steče (cron izpade, workflow onemogočen), ostane neopažena; zagon brez secreta izpiše samo opozorilo.

**Račun `agent@outly.si`:** je obstoječi servisni admin račun (migracija 007; brez CAPTCHA/MFA, `email_verified`). Izvoz zahteva vlogo `admin` (`admin.use(requireAuth, requireRole("admin"))`),
račun pa lahko v admin panelu vse; zato geslo pozna samo GitHub in Martin. *Predlog (ni implementirano):* vloga `backup` samo za izvoz, da uhajanje gesla ne pomeni polne admin pravice.

## Preizkus obnove z workflowom (agent, brez gesla)

Actions → *Preizkus kopije (mesecni)* → *Run workflow* (veja `main`), polje `kopija`: prazno = najnovejša, ali ime kopije (`outly-db-YYYY-MM-DD-r<številke>.json.gz.gpg`).
Agent ga lahko sproži prek GitHub API (`POST /repos/Djurdje/outly-backend/actions/workflows/obnova-preizkus.yml/dispatches`, `{"ref":"main","inputs":{"kopija":"…"}}`) in prebere rezultat zagona:
workflow odsifrira kopijo v runnerju, obnovi jo v `postgres:16` in primerja tabele; **geslo ne zapusti GitHuba**, agent dobi samo zeleno/rdeče in imena tabel. Ta preizkus ne piše v produkcijo.
Za obnovo v produkcijo ali novo bazo gre kopija k Martinu (spodaj).

## Prenos in dešifriranje (Martin, Windows/PowerShell; enako na Linuxu)

Potrebuješ geslo iz upravljalnika gesel (`BACKUP_GESLO`) in GnuPG (Windows: Gpg4win, https://gnupg.org; Linux: `gpg` je običajno že nameščen).

1. Prenesi iz R2: Cloudflare → R2 → `outly-kopije` → `kopije/YYYY/MM/` → `outly-db-YYYY-MM-DD-r<številke>.json.gz.gpg` in njen `….sha256` → *Download*.
   (Ali z `aws` CLI: `aws s3 cp s3://outly-kopije/kopije/YYYY/MM/<ime> . --endpoint-url https://<ACCOUNT_ID>.eu.r2.cloudflarestorage.com --region auto` s ključi R2 v okolju.)
2. Preveri celovitost: `Get-FileHash .\outly-db-YYYY-MM-DD-r<številke>.json.gz.gpg -Algorithm SHA256` mora dati isti odtis kot v `….sha256` (Linux: `sha256sum -c *.sha256`).
3. Dešifriraj (gpg te vpraša za geslo; spremenjena datoteka ali napačno geslo se zavrneta):
   `gpg --decrypt --output izvoz.json.gz outly-db-YYYY-MM-DD-r<številke>.json.gz.gpg`
4. Razpakiraj (deluje povsod, kjer je Node): `node -e "require('fs').writeFileSync('izvoz.json', require('zlib').gunzipSync(require('fs').readFileSync('izvoz.json.gz')))"`
5. Hiter pregled: `node _orodja/kopija/stevila.js povzetek izvoz.json` (iz korena klona repozitorija) — izpiše čas izvoza, tabele in števila vrstic;
   izvoz je cel, če piše »Izvoz je cel«.
6. **Izvoz vsebuje osebne podatke in odtise gesel.** Hrani ga samo zasebno (`outly/backup/YYYY-MM-DD/` na Martinovem računalniku), nikoli v git. Po preizkusu izbriši `izvoz.json` in `izvoz.json.gz`.

## Obnova v novo bazo

Pogoj: klon repozitorija na commitu, katerega migracije ustrezajo izvozu (običajno trenutni `main`; če `db/obnovi_izvoz.js` javi, da se seznam migracij ne ujema,
vzemi commit iz dneva izvoza), `npm ci`, PostgreSQL **16**.

1. **Nova prazna baza.** Lokalno (`postgres://postgres:…@localhost:5432/outly_obnova`, v URL-ju mora pisati `localhost`) ali nova Render baza (**stane denar → Martinov DA**).
   Nikoli obstoječa produkcijska: skripta take zavrne.
2. `DATABASE_URL=<nova baza>` → `npm run migrate` (shema + servisni račun iz migracije 007).
3. `DELETE FROM users WHERE email='agent@outly.si';` (edini seed migracij; izvoz ga že vsebuje — past v STATE.md). Lokalno to naredi tudi
   `node _orodja/kopija/stevila.js pocisti-seed`.
4. `node db/obnovi_izvoz.js izvoz.json` (za cilj, ki ni `localhost`: dodaj `--cilj-ni-localhost`). Pričakovano: število vrstic po tabelah in »Obnova končana«.
   Napaka sredi poti = ROLLBACK, cilj ostane prazen.
5. Neodvisna primerjava: `node _orodja/kopija/stevila.js primerjaj izvoz.json` (cilj mora biti `localhost`) → »vse tabele se ujemajo«.
6. Zaženi backend na novi bazi (lokalno `npm start` z `DATABASE_URL`) in preveri `GET /clubs`, `GET /events` → 200, `GET /me/invites` brez žetona → 401.

## Obnova v produkcijo (samo z Martinovim DA)

Najprej preveri, ali ne zadošča **Renderjeva obnova na točko v času** (zadnji 3 dnevi, delovni prostor Hobby): ta ustvari novo instanco, brez te kopije.
Kopijo uporabi, ko je napaka starejša od 3 dni, ko je izgubljen Render račun ali ko je pokvarjena baza in Renderjeva obnova ni mogoča.

1. Povej Martinu, kaj bo stalo (nova Render baza ≈ 6 $/mesec za `0.1c-256mb`, na koncu staro pobrisati) in kaj se izgubi (spodaj). Počakaj na DA.
2. Martin ustvari novo bazo v Frankfurtu (PostgreSQL 16) in v njenih *Inbound IP Rules* **začasno** doda svoj IP (STATE.md: sicer External URL ne dela).
3. Koraki 2–5 iz razdelka »Obnova v novo bazo« z External URL nove baze, v Martinovem terminalu (z `--cilj-ni-localhost`).
4. Render → `outly-backend` → Environment → `DATABASE_URL` = **Internal** URL nove baze (to je sprememba nastavitev na Renderju: DA). Deploy.
5. Preveri produkcijo: `GET /clubs`, `GET /events` → 200, `GET /me/invites` brez žetona → 401, `outly.si` → 200; workflow `Nadzor produkcije` zelen.
6. Odstrani Martinov IP iz Inbound IP Rules. Staro bazo pobriši šele, ko je jasno, da je ne rabimo (DA).
7. Dopiši vrstico v `docs/INCIDENTI.md`; v `STATE.md` novo ime/ID baze.

**Kaj se izgubi ali zapleta po obnovi iz kopije:**
- Vse po času izvoza (do 24 h): naročila, vstopnice, registracije. Stripe plačila v tem oknu preveri v Stripe nadzorni plošči.
- Obnova **oživi vstopnice, ki so bile skenirane po izvozu** — pred dogodkom naredi svež izvoz ali ročno zaženi workflow tik pred obnovo, če je baza še brana.
- Supabase uporabniki niso v kopiji; `users.supabase_uid` se obnovi, prijava deluje, če je Supabase projekt isti.

## Preizkus, ki ga ne more narediti workflow (Martin, po želji)

Mesečni samodejni preizkus dokazuje, da geslo v GitHubu odpre kopijo v R2 in da je ta obnovljiva. Ne dokazuje, da **geslo v upravljalniku gesel** enako: enkrat po nastavitvi
(in ob menjavi gesla) naredi »Prenos in dešifriranje« 1–5 z najnovejšo kopijo in geslom iz upravljalnika (vpišeš ga ročno), nato izbriši `izvoz.json*`.
Če se ne odpre, sta gesli različni: takoj popravi (secret ali upravljalnik), ne čez mesec.

## Menjava gesla in R2 žetona

- **`BACKUP_GESLO`:** nova kopija se šifrira z novim geslom, **stare kopije ostanejo šifrirane s starim** (do 30 dni). Zato: staro geslo hrani v upravljalniku, dokler obstajajo kopije zanj
  (ali počakaj 30 dni po menjavi). Mesečni preizkus in prenos izbereta kopijo po imenu: za staro kopijo potrebuješ staro geslo (agentov preizkus s `kopija` jo bo zavrnil z napako odsifriranja).
  Ob sumu, da je geslo ušlo: novo geslo takoj, `R2` token tudi; kopije so v zasebnem bucketu, a presodi, ali je kdo imel dostop do secretov.
- **R2 token:** Cloudflare → R2 → Manage API tokens → *Roll* ali nov token (isto dovoljenje, isti bucket) → nova *Access Key ID*/*Secret* v environment `kopije`; star token prekliči.
  Ob poteku tokena zagon pade z `R2: napaka … AccessDenied` (ali `InvalidAccessKeyId`).

## Če dnevna kopija pade

| Znak v dnevniku | Pomen | Ukrep |
|---|---|---|
| `Branch not allowed` / job se ne zažene | zagon ne z veje `main` (environment `kopije`) | zaženi z `main` |
| `Manjka nastavitve v environmentu kopije: …` | secret ni vpisan v environment | Nastavitev (4 secreti) |
| `BACKUP_GESLO je prekratko` / `ne sme vsebovati novih vrstic` | geslo < 32 znakov ali večvrstično | novo geslo (črke in številke, 40 znakov) |
| `Odsifriranje ni uspelo (napacno BACKUP_GESLO …)` | geslo v secretu se razlikuje od tistega, s katerim je bila šifrirana kopija (menjava gesla), ali je datoteka v R2 spremenjena | za novo kopijo ni težava; za staro potrebuješ staro geslo; preveri tudi sha256 |
| `Odsifrirana kopija iz R2 se ne ujema z izvozom` | napaka pri šifriranju ali nalaganju | ponovi zagon; če se ponovi, INCIDENTI |
| `R2: napaka (…): AccessDenied` / `InvalidAccessKeyId` / `SignatureDoesNotMatch` | token potekel, napačen ključ ali token ni za ta bucket | nov token (Menjava ključev), preveri `R2_*` |
| `R2: napaka (…): NoSuchBucket` ali `vedro ni dosegljivo` | napačen `R2_BUCKET` ali bucket ni ustvarjen z jurisdikcijo EU (endpoint `.eu.`) | preveri ime; bucket mora biti ustvarjen s »Specify jurisdiction → European Union«; sicer ga izbriši (je prazen) in ustvari znova |
| `R2: napaka (…): povezava ali neznano` | napačen `R2_ACCOUNT_ID` ali izpad Cloudflara | preveri ID računa, ponovi zagon |
| `Kopija v R2 se po prenosu nazaj ne ujema` | okvara pri nalaganju | ponovi zagon; če se ponovi, INCIDENTI |
| `Izhodišče … ni veljaven JSON` (opozorilo) | pokvarjen objekt `kopije/stanje/stevila.json` | en dan brez preverbe padca; če se ponovi 2 zagona zapored, je zagon rdeč: preglej objekt |
| `Prijava … ni uspela (HTTP 400)` | napačen e-naslov/geslo ali uporabnika ni v Supabase | preveri secrets v environmentu, Supabase → Users |
| `Izvoz ni uspel … HTTP 403` | račun v `BACKUP_ADMIN_EMAIL` ni več `admin` v bazi ali e-naslov v Supabase ni potrjen (`email_verified`) | admin panel → Uporabniki → vloga `admin`; Supabase → Users → potrdi e-naslov |
| `Prijava … HTTP 400` s captcha/MFA | CAPTCHA ali obvezen MFA na Supabase | za ta račun izklopi; prijava z geslom iz workflowa ne more rešiti izziva |
| `Izvoz ni uspel … HTTP 401` | žeton zavrnjen (JWKS/Supabase) | preveri nadzor produkcije, ponovi |
| `Izvoz ni uspel … 5xx` / koda 18, 56 | backend ali baza izpadla, deploy v teku | ponovi zagon; če se ponovi, INCIDENTI + `Nadzor produkcije` |
| `Preizkus obnove kopije baze je padel` (issue `agent`) | mesečni preizkus: geslo, sha256, migracije ali obnova | sledi zagonu in tej tabeli; po popravku ponovi zagon in dopiši INCIDENTI |
| `Hramba: …` ne pade, a kopij je malo | brisanje je preagresivno ali kopije ne nastajajo | `cisti_stare.sh` vedno pusti 7 najnovejših; preveri, zakaj kopije ne nastajajo |
| `Seznam migracij v cilju se ne ujema z izvozom` | main ima novejšo migracijo, ki je produkcija še nima (deploy v teku/padel) | počakaj na deploy in ponovi; kopija je bila vseeno shranjena |
| `Preverba … tabela migrirane sheme MANJKA v izvozu` | izvoz ne vsebuje vse tabele (napaka izvoza ali ročno spremenjen izvoz) | kopija ni popolna: ponovi zagon, če se ponovi, INCIDENTI + preglej `GET /admin/api/export` |
| `Sumljiv padec … users/orders/tickets` | število vrstic je padlo za > 20 % glede na prejšnji zagon | preveri, ali je bilo brisanje namerno; če je, zaženi ročno s `potrdi_padec = true` |
| `Obnova izvoza je padla` + »podrobnosti skrite« | nepričakovana napaka (lahko vsebuje vrednosti) | prenesi kopijo in obnovi lokalno po tem skillu |

Tri zaporedne rdeče kopije = sum na resnično napako, ne na naključje: zapiši v `docs/INCIDENTI.md`.
