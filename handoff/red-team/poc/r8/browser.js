const { chromium } = require('playwright');
const [port, evilPort] = process.argv.slice(2);
(async () => {
  const b = await chromium.launch(); const pg = await b.newPage();
  await pg.goto(`http://localhost:${evilPort}/`);
  const r = await pg.evaluate(async (u) => { const out = {};
    try { await fetch(u+'/api/capture',{method:'POST',mode:'no-cors',headers:{'Content-Type':'text/plain'},body:JSON.stringify({title:'x',body:'planted',tags:[]})}); out.nocors='sent' } catch(e) { out.nocors='err' }
    try { const r = await fetch(u+'/api/lock',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}); out.cors=r.status } catch(e) { out.cors='blocked' }
    return out }, `http://127.0.0.1:${port}`);
  console.log('attacker page:', JSON.stringify(r));
  await pg.goto(`http://127.0.0.1:${port}/`);
  const s = await pg.evaluate(async () => { const d = await fetch('/api/dashboard'); const a = await fetch('/api/ask',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question:'hello'})}); return [d.status, a.status] });
  console.log('studio page same-origin:', JSON.stringify(s), 'title:', await pg.title());
  await b.close();
})();
