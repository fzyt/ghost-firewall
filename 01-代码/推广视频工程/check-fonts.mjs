// 字体覆盖守卫：每个字体栈里必须至少有一个字体能画出工程里用到的全部汉字。
//
// 为什么需要它（2026-11-18 实测踩坑）：
//   JetBrains Mono 只有 976 个码位，**一个汉字都没有**。
//   页面里把中文塞进 '"JetBrains Mono", monospace' 时，Chromium 会回退到列表里的
//   通用 monospace —— 开发机恰好装了带 CJK 的等宽字体，看着正常；
//   渲染主机（do）没有 ⇒ 成片里就是「长方形中间一个叉叉」的豆腐块。
//   本地静帧看不出来，只有成片才发现。
//
// 判据：解析本地字体文件的 cmap（真实字形覆盖），不看字体名。
// 用法：node check-fonts.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));

// ---------- 读 TTF 的 cmap，得到真实覆盖的码位 ----------
function readCodePoints(file) {
  const buf = fs.readFileSync(file);
  const numTables = buf.readUInt16BE(4);
  let cmapOff = 0;
  for (let i = 0; i < numTables; i++) {
    const rec = 12 + i * 16;
    if (buf.toString('latin1', rec, rec + 4) === 'cmap') {
      cmapOff = buf.readUInt32BE(rec + 8);
      break;
    }
  }
  if (!cmapOff) throw new Error(`${file} 没有 cmap 表`);
  const n = buf.readUInt16BE(cmapOff + 2);
  const set = new Set();
  for (let i = 0; i < n; i++) {
    const rec = cmapOff + 4 + i * 8;
    const off = cmapOff + buf.readUInt32BE(rec + 4);
    const format = buf.readUInt16BE(off);
    if (format === 4) {
      const segX2 = buf.readUInt16BE(off + 6);
      const seg = segX2 / 2;
      const endO = off + 14;
      const startO = endO + segX2 + 2;
      for (let s = 0; s < seg; s++) {
        const end = buf.readUInt16BE(endO + s * 2);
        const start = buf.readUInt16BE(startO + s * 2);
        if (start === 0xffff) continue;
        for (let c = start; c <= end && c !== 0x10000; c++) set.add(c);
      }
    } else if (format === 12) {
      const nGroups = buf.readUInt32BE(off + 12);
      for (let g = 0; g < nGroups; g++) {
        const rec2 = off + 16 + g * 12;
        const start = buf.readUInt32BE(rec2);
        const end = buf.readUInt32BE(rec2 + 4);
        for (let c = start; c <= end; c++) set.add(c);
      }
    }
  }
  return set;
}

// ---------- fonts.css：family → 字体文件 ----------
const css = fs.readFileSync(path.join(ROOT, 'shared/fonts.css'), 'utf8');
const familyFiles = new Map();
for (const m of css.matchAll(/font-family:\s*"([^"]+)"[\s\S]*?src:\s*url\("([^"]+)"\)/g)) {
  familyFiles.set(m[1], path.join(ROOT, m[2].replace(/^\//, '')));
}

const familyCoverage = new Map();
for (const [fam, file] of familyFiles) {
  if (!fs.existsSync(file)) {
    console.error(`字体文件缺失：${fam} → ${file}`);
    process.exit(1);
  }
  familyCoverage.set(fam, readCodePoints(file));
}

// ---------- 工程里用到的非 ASCII 字符 ----------
// 不只汉字：全角标点、箭头、emoji（✅ 等）都可能是豆腐块，
// 一并纳入 —— 只要画出来的字符不在某个本地字体的 cmap 里，成片上就是方框。
const srcFiles = [
  ...fs.readdirSync(path.join(ROOT, 'segments')).filter((f) => f.endsWith('.html')).map((f) => path.join(ROOT, 'segments', f)),
];


// ---------- 收集每个源文件里的字体栈与字符 ----------
// 判据按**文件**判定：文件里出现的每个非 ASCII 字符，必须能被该文件用到的
// 某个本地字体覆盖。不做逐调用点的数据流分析 —— 因为字体栈里已经带了
// "Noto Sans SC" 兜底，同一文件里只要有一个字体能画，就不会再出豆腐块。
//
// 字体名的收集有两路：
//   1) ctx.font = '...' / `...` 字面量里的字体栈；
//   2) 源码里以字符串形式出现的已知本地字体名（如 const SANS = '"Noto Sans SC", sans-serif'），
//      —— 页面把字体栈收进常量、再由 setFont() 统一设置时，只有第 2 路能看得到。
const problems = [];
let stackCount = 0;
for (const f of srcFiles) {
  const src = fs.readFileSync(f, 'utf8');

  const stacks = [
    ...[...src.matchAll(/ctx\.font\s*=\s*'([^']*)'/g)].map((m) => m[1]),
    ...[...src.matchAll(/ctx\.font\s*=\s*`([^`]*)`/g)].map((m) => m[1]),
  ];
  const fams = new Set();
  for (const stack of stacks) {
    stackCount++;
    for (const m of stack.matchAll(/"([^"]+)"/g)) fams.add(m[1]);
  }
  // 第 2 路：源码里引用到的已知本地字体名
  for (const fam of familyCoverage.keys()) {
    if (src.includes(`"${fam}"`) || src.includes(`'${fam}'`)) fams.add(fam);
  }

  const fileChars = new Set();
  for (const ch of src) {
    if (ch.codePointAt(0) >= 128) fileChars.add(ch.codePointAt(0));
  }

  // 本文件用到的字体里，有没有任何一个能画出文件里的全部字符
  const capable = [...fams].filter((fam) => {
    const cps = familyCoverage.get(fam);
    if (!cps) return false;
    for (const cp of fileChars) if (!cps.has(cp)) return false;
    return true;
  });

  if (!capable.length) {
    // 逐字符找出到底是谁画不了
    const undrawable = [...fileChars].filter((cp) =>
      ![...fams].some((fam) => (familyCoverage.get(fam) || new Set()).has(cp)));
    problems.push({
      file: path.basename(f),
      fams: [...fams],
      undrawable: undrawable.map((cp) => ({
        cp,
        ch: String.fromCodePoint(cp),
        who: [...fams].filter((fam) => !(familyCoverage.get(fam) || new Set()).has(cp)),
      })),
    });
  }
}

console.log(`本地字体 ${familyCoverage.size} 个，检查 ${stackCount} 处字体栈 / ${srcFiles.length} 个源文件`);
for (const [fam, cps] of familyCoverage) {
  console.log(`  ${fam.padEnd(22)} 覆盖 ${cps.size} 码位`);
}

if (problems.length) {
  console.error(`\n${problems.length} 个文件里有字符是本文件的字体画不出来的（会渲染成豆腐块）：`);
  for (const p of problems) {
    console.error(`  ${p.file}  字体：${p.fams.join(', ')}`);
    for (const u of p.undrawable) {
      console.error(`    U+${u.cp.toString(16).toUpperCase().padStart(4, '0')}  ${JSON.stringify(u.ch)}  缺字形：${u.who.join(', ')}`);
    }
  }
  console.error('\n修法：把该字符换成字体有的字，或自己画（不依赖字体）');
  process.exit(1);
}
console.log('\n全部字符都有字形：通过');
