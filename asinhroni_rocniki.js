// Varovalo za asinhrone rocnike Expressa 4 (issue #129).
//
// Express 4 vrnjene obljube rocnika NE ujame: `app.post(pot, async (req, res) => { const c = await pool.connect(); try {...} })`
// ob zavrnjeni `pool.connect()` ("timeout exceeded when trying to connect", izcrpan pool) ni ujel nihce -> unhandled rejection
// -> Node 22 konca CEL proces (tudi sken vstopnic na vratih). Express 5 to resi sam; tu je enak ovoj za Express 4:
// zavrnitev rocnika ali vmesnega programa gre v `next(err)` in ju obravnava napakaRocnik (spodaj).
//
// Zakaj ovoj in ne `process.on("unhandledRejection")`: ta bi proces pustil pri zivljenju, a zahtevek bi ostal brez odgovora
// (odjemalec caka do timeouta) in proces bi lahko ostal v nedolocenem stanju (odprta transakcija, neizposojena povezava).
// Ovoj odjemalcu vedno vrne odgovor, napako pa pripelje do ene tocke, kjer se zapise in prevede.
//
// Ovoj poseze v Layer.prototype.handle_request (notranjost Expressa 4.x, enako dela paket express-async-errors), zato velja za
// VSE poti: app, Router (admin) in vmesne programe, brez spreminjanja 77 poti. Ce poti ni (Express 5 ali druga razlicica),
// require pade ob zagonu (deploy pade, stara razlicica ostane) - ne tiho brez varovala.
const Layer = require("express/lib/router/layer");
const { jeNapakaPovezave } = require("./napaka_povezave");

let namescen = false;
function namestiAsinhroniOvoj() {
  if (namescen) return;
  namescen = true;
  Layer.prototype.handle_request = function handle_request(req, res, next) {
    const fn = this.handle;
    if (fn.length > 3) return next();   // obravnavalnik napak (4 argumenti) pri navadnem zahtevku ne teče
    try {
      const r = fn(req, res, next);
      if (r && typeof r.then === "function") r.then(undefined, next);   // zavrnjena obljuba -> next(err), ne unhandled rejection
    } catch (err) {
      next(err);
    }
  };
}

// Express obravnavalnik napak (4 argumenti), registriran PO vseh poteh.
//  - odgovor ze (delno) poslan: dvojnega ne pisemo; napako zapisemo in prepustimo Expressu, ki zapre povezavo;
//  - napaka body-parserja ali druga 4xx (err.status / statusCode): ostane, kot je bila (privzeti obravnavalnik Expressa);
//  - napaka povezave/baze (isto merilo kot pri iskanju kluba): 503 + Retry-After 5 (I10), uporabnik ostane prijavljen;
//  - vse drugo: 500 s polnim skladom v dnevniku.
function napakaRocnik(err, req, res, next) {
  const status = Number(err && (err.status || err.statusCode));
  if (res.headersSent) {
    console.error("[rocnik] napaka po poslanem odgovoru:", (err && err.stack) || err);
    return next(err);
  }
  if (status >= 400 && status < 500) return next(err);
  if (jeNapakaPovezave(err)) {
    console.error("[rocnik] zacasna napaka povezave z bazo:", (err && err.message) || err);
    return res.status(503).set("Retry-After", "5").send("Service temporarily unavailable. Please try again.");
  }
  console.error("[rocnik] nepricakovana napaka:", (err && err.stack) || err);
  return res.status(500).send("Server error.");
}

module.exports = { namestiAsinhroniOvoj, napakaRocnik };
