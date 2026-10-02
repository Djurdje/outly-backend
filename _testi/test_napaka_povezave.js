#!/usr/bin/env node
/**
 * Unit test napaka_povezave.js (issue #125): katere napake iz baze/poola so zacasna tezava (503) in katere ostanejo 500.
 * Zagon: node _testi/test_napaka_povezave.js (baze ne rabi)
 */
const { jeNapakaPovezave } = require("../napaka_povezave");
let ok = 0, fail = 0;
function assert(cond, msg) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg); } }
const z = (code, message = "x") => Object.assign(new Error(message), { code });

console.log("Napake povezave -> 503:");
assert(jeNapakaPovezave(z("EPIPE")), "EPIPE (5 znakov, a omrezna koda, ne SQLSTATE)");
assert(jeNapakaPovezave(z("ECONNRESET")), "ECONNRESET");
assert(jeNapakaPovezave(z("ECONNREFUSED")), "ECONNREFUSED");
assert(jeNapakaPovezave(z("ETIMEDOUT")), "ETIMEDOUT");
assert(jeNapakaPovezave(z("ENOTFOUND")), "ENOTFOUND");
assert(jeNapakaPovezave(z("EAI_AGAIN")), "EAI_AGAIN");
assert(jeNapakaPovezave(z("57P01")), "57P01 admin_shutdown");
assert(jeNapakaPovezave(z("57P03")), "57P03 cannot_connect_now");
assert(jeNapakaPovezave(z("53300")), "53300 too_many_connections");
assert(jeNapakaPovezave(z("08006")), "08006 connection_failure");
assert(jeNapakaPovezave(new Error("timeout exceeded when trying to connect")), "pg brez kode: timeout exceeded when trying to connect");
assert(jeNapakaPovezave(new Error("Connection terminated unexpectedly")), "pg brez kode: Connection terminated unexpectedly");
assert(jeNapakaPovezave(new Error("Query read timeout")), "pg brez kode: Query read timeout");
console.log("Ostane 500:");
assert(!jeNapakaPovezave(z("40P01")), "40P01 deadlock_detected");
assert(!jeNapakaPovezave(z("22003")), "22003 numeric_value_out_of_range");
assert(!jeNapakaPovezave(z("42P01")), "42P01 undefined_table");
assert(!jeNapakaPovezave(z("23505")), "23505 unique_violation");
assert(!jeNapakaPovezave(new TypeError("Cannot read properties of undefined (reading 'connect')")), "TypeError (tudi ce sporocilo vsebuje connect)");
assert(!jeNapakaPovezave(new ReferenceError("x is not defined")), "ReferenceError");
assert(!jeNapakaPovezave(new Error("nekaj povsem drugega")), "napaka brez kode in brez znakov povezave");
assert(!jeNapakaPovezave(null) && !jeNapakaPovezave(undefined), "null / undefined");
console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
process.exit(fail ? 1 : 0);
