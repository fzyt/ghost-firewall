// 静态体检：找出「用到了 common.js/themes.js 的导出，但没 import」的名字
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');

const exported = new Set();
for (const f of ['common.js', 'themes.js']) {
  for (const m of read(f).matchAll(/export\s+(?:async\s+)?(?:function|const|let|class)\s+([A-Za-z_$][\w$]*)/g)) {
    exported.add(m[1]);
  }
  for (const m of read(f).matchAll(/export\s*\{([^}]*)\}/g)) {
    for (const part of m[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/).pop().trim();
      if (name) exported.add(name);
    }
  }
}

const files = fs.readdirSync(path.join(ROOT, 'segments')).filter((f) => f.endsWith('.html'));
let bad = 0;
for (const f of files) {
  const src = read(path.join('segments', f));
  const imported = new Set();
  for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from/g)) {
    for (const part of m[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/)[0].trim();
      if (name) imported.add(name);
    }
  }
  // 本文件自己声明的名字（函数/常量），不算缺失
  const local = new Set();
  for (const m of src.matchAll(/(?:function|const|let|var)\s+([A-Za-z_$][\w$]*)/g)) local.add(m[1]);
  for (const m of src.matchAll(/(?:const|let)\s*\{([^}]*)\}\s*=/g)) {
    for (const part of m[1].split(',')) local.add(part.trim().split(':').pop().trim());
  }

  const missing = [...exported].filter((name) => {
    if (imported.has(name) || local.has(name)) return false;
    return new RegExp(`(^|[^.\\w$])${name}\\s*\\(`).test(src);
  });
  if (missing.length) {
    bad++;
    console.log(`[缺] ${f}: ${missing.join(', ')}`);
  }
}
console.log(bad ? `发现 ${bad} 个文件有未导入符号` : '全部通过：没有未导入的公共库符号');
