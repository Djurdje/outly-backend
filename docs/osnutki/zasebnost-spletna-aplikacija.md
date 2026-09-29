# OSNUTEK — dopolnitev Politike zasebnosti za spletno aplikacijo (outly.si/app)

**Stanje: NI objavljeno. Čaka na Martinov DA** (pravni dokument — DECISIONS 29. 9. 2026). Ko Martin potrdi, agent
spremeni `privacy-app.html` (SL, merodajna) in `privacy.html` (EN), dvigne različico (2.3 → 2.4) in datum.
Obstoječa besedila (različica 2.3, 24. 9. 2026) ostanejo; spodaj so samo **spremembe** po razdelkih.

Kaj spletna aplikacija dejansko počne (preverjeno v kodi `outly_webpage`, faze 1–5):
- isti račun, isti strežnik in ista baza kot aplikacija; nov odjemalec, nobenih novih vrst podatkov na strežniku;
- v brskalniku hrani: sejo prijave, izbrani jezik, »My preferences« (samo v brskalniku, izbrišejo se ob odjavi),
  izbiro obraza profila lastnika kluba (klubski/osebni); service worker hrani **samo kodo aplikacije** (HTML, CSS, JS,
  pisavo, ikone) — nobenih odgovorov strežnika, vstopnic ali osebnih podatkov;
- lokacija: samo na gumb »Use my location«, ostane v brskalniku, na strežnik ne gre;
- zemljevid: podatki OpenStreetMap (prek Protomaps) z naše domene outly.si — noben ponudnik zemljevidov ne dobi zahtev;
- lastnik kluba lokacijo kluba označi s klikom na zemljevid (koordinate kluba so že navedene med podatki poslovnih računov);
- kamere spletna aplikacija ne uporablja (skener vstopnic je samo v aplikaciji Outly);
- brez piškotkov, analitike, oglasnih pikslov; knjižnice in pisava z naše domene;
- slike in videi se nalagajo neposredno s strežnikov Cloudinary (že navedenega obdelovalca), kot v aplikaciji.

---

## Slovensko (`privacy-app.html`)

**Glava:** »Veljavna od [datum] · različica 2.4 · velja za aplikacijo Outly, spletno aplikacijo na outly.si/app in
spletno stran outly.si«

**§2 Kaj zbiramo — nov podrazdelek za »Na spletni strani outly.si«:**

> ### V spletni aplikaciji (outly.si/app)
> Spletna aplikacija je različica aplikacije Outly za brskalnik. Uporablja isti račun, isti strežnik in iste podatke
> kot aplikacija, zato zanjo velja vse, kar je v tej politiki napisano za aplikacijo. Novih vrst podatkov na naših
> strežnikih ne zbira.

**§7 Lokacija — dodaj odstavek:**

> V spletni aplikaciji brskalnik za lokacijo vpraša šele, ko tapneš »Use my location«. Tudi tam lokacije ne pošiljamo
> na strežnik in je ne shranjujemo; ostane v brskalniku, dokler je stran odprta. Dostop lahko kadarkoli prekličeš v
> nastavitvah brskalnika. Zemljevid v spletni aplikaciji uporablja podatke OpenStreetMap, ki jih strežemo z naše
> domene — zahteve za zemljevid ne gredo k nobenemu drugemu ponudniku.

**§8 Spletna stran: piškotki in zunanje vsebine — nadomesti seznam lokalne shrambe:**

> V lokalni shrambi brskalnika (localStorage) hranimo samo, kar je nujno za storitev, ki jo zahtevaš:
> - sejo prijave, če se prijaviš — da ostaneš prijavljen (velja za spletno stran in spletno aplikacijo);
> - kodo povabila, če si prišel prek povezave prijatelja — da se točka pripiše pravi osebi. Po prijavi na čakalno
>   listo jo izbrišemo;
> - v spletni aplikaciji še: izbrani jezik, nastavitve »My preferences« (izbrišemo jih ob odjavi) in pri lastnikih
>   klubov izbiro, ali se v profilu prikaže klub ali osebni račun.
>
> Spletna aplikacija za hitrejše odpiranje in delovanje brez povezave v brskalniku shrani **svojo programsko kodo**
> (predpomnilnik service workerja). Tam niso shranjeni tvoji podatki, vstopnice ali odgovori našega strežnika.
> Vse to izbrišeš tako, da v nastavitvah brskalnika izbrišeš podatke strani outly.si.
>
> Če spletno aplikacijo dodaš na začetni zaslon telefona, se odpira kot aplikacija; to ne spremeni, katere podatke
> obdelujemo.

(Stavek »Stran ne vsebuje vdelanih vsebin tretjih oseb (videi, zemljevidi, gumbi družbenih omrežij)« ostane resničen,
ker zemljevid gostimo sami.)

**§11 Varnost — popravi alinejo o žetonu (danes ni točna za splet):**

> - Prijavni žeton je v aplikaciji shranjen v varni shrambi sistema telefona; na spletni strani in v spletni
>   aplikaciji pa v lokalni shrambi brskalnika. Spletna aplikacija ima zato strogo varnostno politiko vsebine (CSP),
>   ki dovoli samo kodo z naše domene.

---

## English (`privacy.html`)

**Header:** »Last updated: [date] · version 2.4 · applies to the Outly app, the web app at outly.si/app and outly.si«

**§2 What we collect — new block:**

> **Web app (outly.si/app).** The web app is the browser version of the Outly app. It uses the same account, server
> and data as the app, so everything this policy says about the app also applies to it. It does not collect any new
> kinds of data on our servers.

**Location — add:**

> In the web app, your browser asks for your location only when you tap “Use my location”. Your location is not sent
> to our servers or stored; it stays in your browser while the page is open. You can revoke access in your browser
> settings at any time. The web app’s map uses OpenStreetMap data served from our own domain — map requests do not go
> to any other provider.

**Local storage — replace the list:**

> We keep only what the service you asked for needs in your browser’s local storage (localStorage):
> - your sign-in session, if you sign in (website and web app);
> - a friend’s invite code, if you came through an invite link — removed once you join the waitlist;
> - in the web app also: your chosen language, “My preferences” (removed when you log out) and, for club owners,
>   whether the profile shows the club or the personal account.
>
> To open faster and work without a connection, the web app stores **its own code** in the browser (service worker
> cache). None of your data, tickets or responses from our server are stored there. You can remove all of this by
> clearing site data for outly.si in your browser settings.

**Security — correct the token sentence:**

> - In the app, the sign-in token is stored in the phone’s secure system storage; on the website and in the web app it
>   is stored in the browser’s local storage. The web app therefore uses a strict Content Security Policy that allows
>   only code from our own domain.

---

## Odprto za Martina
1. DA na besedilo zgoraj (ali popravki).
2. Ali naj pred objavo spletne aplikacije (gumb na outly.si) obvestimo uporabnike o spremembi po e-pošti — po §12
   (»o bistvenih spremembah te obvestimo«). Predlog agenta: to ni bistvena sprememba (novih podatkov ni), zato zadošča
   nov datum in različica.
