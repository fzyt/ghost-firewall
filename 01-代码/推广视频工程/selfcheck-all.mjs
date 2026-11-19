// 全片自检：9 段逐段验导出契约、逐帧无异常、同 t 重绘像素一致、禁用 API、文案与 timeline 对齐
// 用法：node selfcheck-all.mjs
// 依赖：工程根 package.json 里的 playwright-core（工程自带独立 package.json，不会向上解析到别处）
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.ttf': 'font/ttf', '.otf': 'font/otf',
};
const FORBIDDEN = [
  /Math\.random\s*\(/, /Date\.now\s*\(/, /new\s+Date\s*\(/,
  /requestAnimationFrame/, /setTimeout\s*\(/, /setInterval\s*\(/,
];

// 画面必须是 t 的纯函数：这四个是动画/随机源，一旦出现就无法保证同 t 同像素
function startServer(root) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
      if (p.endsWith('/')) p += 'index.html';
      const file = path.resolve(root, '.' + p);
      if (!file.startsWith(root + path.sep)) { res.writeHead(403).end(); return; }
      fs.stat(file, (err, st) => {
        if (err || !st.isFile()) { res.writeHead(404).end('404'); return; }
        res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' });
        fs.createReadStream(file).pipe(res);
      });
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

// 把 timeline 的 copy 字段摊平成字符串列表：每个文案都必须在页面源码里逐字出现
// 注意：文案可能为了排版被拆成多段分别绘制（如 s05 把 N 和 1 单独放大），
// 所以比对按分隔符拆成原子 —— 整串连续匹配会把「拆行渲染」误判成漏字。
function flattenCopy(node, out = []) {
  if (typeof node === 'string') out.push(node);
  else if (Array.isArray(node)) node.forEach((n) => flattenCopy(n, out));
  else if (node && typeof node === 'object') Object.values(node).forEach((v) => flattenCopy(v, out));
  return out;
}

// 拆成原子：按空白 / 破折号 / 换行切，逗号不断（逗号连接的是同一句）
function atoms(s) {
  return s.split(/[\s\u2014\u2013]+/).filter(Boolean);
}

const timeline = JSON.parse(fs.readFileSync(path.join(ROOT, 'timeline.json'), 'utf8'));
const segments = timeline.segments;

const { chromium } = await import('playwright-core');

// 共享模块也要守纯函数契约：它们被所有段落 import，出了随机源整片就不确定
const CORE_FILES = ['common.js', 'themes.js', 'motion.js', 'terminal.js'];
const coreBad = [];
for (const f of CORE_FILES) {
  const p = path.join(ROOT, f);
  if (!fs.existsSync(p)) continue;
  const hits = FORBIDDEN.filter((re) => re.test(fs.readFileSync(p, 'utf8'))).map(String);
  if (hits.length) coreBad.push(`${f}: ${hits.join(', ')}`);
}

const server = await startServer(ROOT);
const port = server.address().port;
const browser = await chromium.launch({
  headless: true,
  args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
});

let failed = 0;
for (const seg of segments) {
  const rel = seg.page.replace(/^\//, '');
  const abs = path.join(ROOT, rel);
  const src = fs.readFileSync(abs, 'utf8');
  const bad = FORBIDDEN.filter((re) => re.test(src)).map(String);
  const missing = flattenCopy(seg.copy).flatMap(atoms).filter((a) => !src.includes(a));

  const url = `http://127.0.0.1:${port}/${rel}?theme=coral-noir&seg=1&t0=${seg.t0}&speed=${seg.speed}&dur=${seg.duration}`;
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction('window.__ready === true || window.__bootError', null, { timeout: 120000 });

  const res = await page.evaluate((dur) => {
    const out = {
      boot: window.__bootError, ready: window.__ready, duration: window.DURATION,
      hasRender: typeof window.renderFrame === 'function',
    };
    let threw = null;
    // 先整段扫一遍，任何一帧抛异常都算失败；顺带把首帧冷启动差异热掉
    for (let t = 0; t <= dur + 1e-9; t += 0.05) {
      try { window.renderFrame(t); } catch (e) { threw = `${t.toFixed(2)}: ${e.message}`; break; }
    }
    out.threw = threw;
    const c = document.getElementById('c');
    const probe = [0, dur * 0.05, dur * 0.25, dur * 0.45, dur * 0.65, dur - 0.5, dur];
    out.diff = [];
    for (const t of probe) {
      window.renderFrame(t);
      const a = c.toDataURL();
      window.renderFrame(t);
      const b = c.toDataURL();
      out.diff.push({ t: +t.toFixed(2), same: a === b });
    }
    return out;
  }, seg.duration);

  const ok = !bad.length && !missing.length && !res.threw && res.hasRender && res.ready === true
    && !res.boot && Math.abs(res.duration - seg.duration) < 1e-6
    && res.diff.every((d) => d.same) && !errors.length;
  if (!ok) failed++;
  console.log(`[${ok ? '通过' : '失败'}] ${seg.id}  ${rel}  ${seg.duration}s`);
  console.log(`   导出: renderFrame=${res.hasRender} DURATION=${res.duration} __ready=${res.ready} __bootError=${res.boot}`);
  console.log(`   逐帧无异常: ${res.threw ? '异常 ' + res.threw : '通过'}`);
  console.log(`   同 t 像素一致: ${res.diff.map((d) => `${d.t}s=${d.same ? '一致' : '不一致'}`).join(' ')}`);
  console.log(`   禁用 API: ${bad.length ? bad.join(', ') : '无'}`);
  console.log(`   文案对齐: ${missing.length ? '缺 ' + missing.length + ' 条 -> ' + missing.join(' | ') : '通过'}`);
  console.log(`   页面报错: ${errors.length ? errors.join(' | ') : '无'}`);
  await page.close();
}

await browser.close();
server.close();
if (coreBad.length) {
  failed++;
  console.error(`\n共享模块里的禁用 API：${coreBad.join('；')}`);
}
console.log(failed ? `\n${failed} 个段落自检失败` : '\n全部段落自检通过');
process.exit(failed ? 1 : 0);
