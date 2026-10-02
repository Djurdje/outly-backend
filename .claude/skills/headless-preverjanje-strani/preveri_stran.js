// Headless preverjanje outly.si razdelka Points: stub Supabase + backend, konzola brez napak,
// mobilna sirina 393 (iPhone 14 Pro) in namizje 1280, posnetki zaslona.
const { chromium } = require('playwright');
const fs = require('fs');
const OUT = __dirname + '/shots';
// Minimalni stub supabase-js (CDN v tem okolju ni dosegljiv): brez seje, RPC vrne prazno.
const STUB_LIB = `window.supabase={createClient:()=>({auth:{getSession:async()=>({data:{session:null},error:null}),getUser:async()=>({data:{user:null},error:null}),onAuthStateChange:()=>({data:{subscription:{unsubscribe(){}}}}),signInWithPassword:async()=>({data:null,error:{message:'stub'}}),signUp:async()=>({data:null,error:{message:'stub'}}),signOut:async()=>({error:null}),resetPasswordForEmail:async()=>({error:null})},rpc:async()=>({data:null,error:null}),from:()=>{const q={select(){return q},order(){return q},limit(){return q},eq(){return q},gt(){return q},then(r){return Promise.resolve({data:[],error:null,count:0}).then(r)}};return q},channel:()=>({on(){return this},subscribe(){return this}}),removeChannel(){}})};`;
fs.mkdirSync(OUT, { recursive: true });

(async () => {
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
  const problems = [];
  for (const [name, vp] of [['mobile', { width: 393, height: 852 }], ['desktop', { width: 1280, height: 900 }]]) {
    const ctx = await browser.newContext({ viewport: vp, deviceScaleFactor: 2, isMobile: name === 'mobile' });
    const page = await ctx.newPage();
    page.on('console', m => { if (m.type() === 'error') problems.push(`[${name}] console: ${m.text()}`); });
    page.on('pageerror', e => problems.push(`[${name}] pageerror: ${e.message}`));
    // Stub vsega, kar ni lokalno: Supabase REST/RPC, backend, fonts.
    await page.route(/^https?:\/\/(?!127\.0\.0\.1)/, route => {
      const u = route.request().url();
      if (u.includes('cdn.jsdelivr.net') && u.includes('supabase')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: STUB_LIB });
      if (u.includes('supabase')) return route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      if (u.includes('onrender')) return route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"stub"}' });
      return route.fulfill({ status: 200, contentType: 'text/css', body: '' });
    });
    await page.goto('http://127.0.0.1:8765/index.html', { waitUntil: 'networkidle' });

    const sec = page.locator('#points');
    if (await sec.count() !== 1) problems.push(`[${name}] #points manjka`);
    const perks = await page.locator('#points .perk').count();
    if (perks !== 4) problems.push(`[${name}] perk count ${perks}`);
    const navPts = await page.locator('nav.nav__links a[href="#points"]').count();
    if (navPts !== 1) problems.push(`[${name}] nav Points link ${navPts}`);
    // Horizontalni overflow?
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (overflow > 1) problems.push(`[${name}] horizontal overflow ${overflow}px`);
    // Posnetek razdelka
    await sec.scrollIntoViewIfNeeded();
    await page.waitForTimeout(400);
    await sec.screenshot({ path: `${OUT}/points-${name}.png` });
    // Gumb "I already have an account" -> odpre plosco (login, ker ni racuna)
    await page.click('#pointsInviteBtn');
    await page.waitForTimeout(500);
    const drawerOpen = await page.evaluate(() => { const d = document.getElementById('authDrawer'); return !!d && !d.hidden && d.classList.contains('is-open'); });
    if (!drawerOpen) problems.push(`[${name}] plosca se po kliku ni odprla`);
    await page.screenshot({ path: `${OUT}/drawer-${name}.png` });
    await ctx.close();
  }
  await browser.close();
  console.log(problems.length ? 'TEZAVE:\n' + problems.join('\n') : 'OK: brez napak v konzoli, brez overflowa, #points + nav + gumb delujejo');
})();
