// Headless preverjanje strani outly.si: stub samo *.supabase.co + backend (supabase-js in fonti so lokalni),
// konzola brez napak, brez vodoravnega overflowa, mobilna sirina 393 (iPhone 14 Pro) in namizje 1280, posnetki.
// Uporaba: node preveri_stran.js [pot=/index.html] [selektor_za_posnetek=body]
const { chromium } = require('playwright');
const fs = require('fs');
const POT = process.argv[2] || '/index.html', SEL = process.argv[3] || 'body';
const OUT = __dirname + '/shots';
fs.mkdirSync(OUT, { recursive: true });

(async () => {
  // Pot do Chromiuma: ls -d /opt/pw-browsers/chromium-*/chrome-linux/chrome (nikoli `playwright install`).
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
  const problems = [];
  for (const [name, vp] of [['mobile', { width: 393, height: 852 }], ['desktop', { width: 1280, height: 900 }]]) {
    const ctx = await browser.newContext({ viewport: vp, deviceScaleFactor: 2, isMobile: name === 'mobile' });
    const page = await ctx.newPage();
    page.on('console', m => { if (m.type() === 'error') problems.push(`[${name}] console: ${m.text()}`); });
    page.on('pageerror', e => problems.push(`[${name}] pageerror: ${e.message}`));
    // Stub samo tega, do cesar seja nima izhoda: Supabase REST/RPC/Auth in backend. Vse ostalo je lokalno.
    // POZOR: page.route izklopi HTTP predpomnilnik brskalnika.
    await page.route(/^https?:\/\/(?!127\.0\.0\.1)/, route => {
      const u = route.request().url();
      if (u.includes('supabase.co')) return route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      if (u.includes('onrender')) return route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"stub"}' });
      problems.push(`[${name}] nepricakovan zunanji vir: ${u}`);
      return route.abort();
    });
    // Realtime (WebSocket) page.route ne zajame: brez tega konzola javi ERR_CERT_AUTHORITY_INVALID za wss://*.supabase.co.
    await page.routeWebSocket(/supabase\.co/, () => {});
    await page.goto('http://127.0.0.1:8765' + POT, { waitUntil: 'networkidle' });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (overflow > 1) problems.push(`[${name}] horizontal overflow ${overflow}px`);
    const el = page.locator(SEL).first();
    if (await el.count() !== 1) problems.push(`[${name}] selektor ${SEL} manjka`);
    else { await el.scrollIntoViewIfNeeded(); await page.waitForTimeout(400); await el.screenshot({ path: `${OUT}/stran-${name}.png` }); }
    await ctx.close();
  }
  await browser.close();
  console.log(problems.length ? 'TEZAVE:\n' + problems.join('\n') : 'OK: brez napak v konzoli, brez overflowa, posnetki v shots/');
})();
