# Stres test — 6. 10. 2026

Testni strežnik `outly-obremenitev-test` (Render Starter 0,5 CPU / 512 MB = enako kot produkcija) + testna baza
`obremenitev-test` (Render Free, 0,1 CPU / 256 MB = **enako kot produkcijska `outly-db`**, plan `0.1c-256mb`).
Izmišljeni podatki: 30 klubov, 200 dogodkov. Orodje: `outly-hq/orodja/stres/` (izhodi v `rezultati/`, niso v repu).
Odjemalec: oblačna seja (en IP, prek agent-proxyja). Odgovori so stisnjeni (`content-encoding: br`). Promet skupaj ~100 MB.

## Rezultat

| Hkratni uporabniki | req/s | p95 | Napake (5xx/timeout) | Stanje |
| --- | --- | --- | --- | --- |
| 25 | 27 | 0,34 s | 0 % | zdravo |
| 50 | 54 | 0,29 s | 0 % | zdravo |
| 100 | 102 | 0,82 s | 0 % | **zadnja zdrava stopnja** |
| 200 | 121–124 | 3,3 s | 0 % | počasno |
| 400 | 114–138 | 6–8 s | 0,02 % | zelo počasno, brez sesutja |
| 800 | — | — | — | ni izmerjeno: odjemalec (naš stroj) nasičen |

- **Ozko grlo: baza.** CPU baze je od 200 uporabnikov naprej na **100 %** (0,1 od 0,1 CPU), aktivnih povezav 13–14.
  Strežnik je imel največ ~0,12 CPU od 0,5 (≈ 24 %) in ≤ 95 MB od 512 MB. Pretok se ustavi pri ~120–150 req/s.
- Merilo pri 200 uporabnikih velja (API zagon: CPU odjemalca povprečje 13 %, proxy 7 %, zamuda zanke 49 ms).
  Stopnje 400+ je odjemalec že omejeval — tam številke niso merilo strežnika.
- **Sesutja ni bilo**; 0 × 5xx v Render metrikah. Okrevanje takoj po koncu obremenitve (`/clubs` 0,35 s).
- **Kaj vidi kupec:** nič ne pade, vse postaja počasnejše. Najprej (dražje poizvedbe): `/events` klub popular,
  `/clubs`, `/clubs/map`, `/search`, `/events/:id`. Hitri ostanejo `/genres` in domači `/events` (p50 ~0,2 s pri 200).
  Nakup gosta (brskalnik) pri 200 uporabnikih p50 7 s.
- **429** (`POST /views`, gostujoči nakup 10/h/IP): posledica enega IP-ja vseh botov, ne napaka strežnika; ne šteje v napake.

## Posledica za zahtevo »1000+ hkratnih uporabnikov«

**Ni izpolnjena.** Pri današnji produkcijski bazi (0,1 CPU) je realna meja tekočega delovanja ~100–150 hkratnih uporabnikov.
Predlogi (Issues z oznako `zanesljivost`): močnejša baza (strošek → Martin) in predpomnjenje najdražjih poizvedb.
Po vsaki spremembi ponovi test — odjemalec iz ene oblačne seje zmore ~400 API uporabnikov, za več rabi več strojev/IP-jev.
