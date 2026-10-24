// Pomozni modul za _testi/test_potrdilo_kupcu.js (zagon backenda z `node -r`): prenos plakata s Cloudinaryja (mail_karta.js) brez omrezja.
// fetch na https://res.cloudinary.com/ vrne majhen JPEG (pot z »ni-slika« vrne HTML) in vsak klic zapise v dnevnik »[test-plakat] <url>«.
// Ni del produkcije in ni v `npm test` (ni testna skripta).
const pravi = global.fetch;
const JPEG = Buffer.from("ffd8ffe000104a46494600010100000100010000ffd9", "hex");
global.fetch = async (url, opt) => {
  const u = String(url);
  if (!u.startsWith("https://res.cloudinary.com/")) return pravi(url, opt);
  console.log(`[test-plakat] ${u}`);
  if (u.includes("ni-slika")) return new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } });
  return new Response(JPEG, { status: 200, headers: { "content-type": "image/jpeg", "content-length": String(JPEG.length) } });
};
