// 按 timeline.json 逐段渲染全片，并生成 concat 用的 segments.txt
import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";
import { fileURLToPath } from "node:url";

// 路径含中文，import.meta.url 的 pathname 会百分号编码，必须走 fileURLToPath
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)));
const TL = JSON.parse(fs.readFileSync(path.join(ROOT, "timeline.json"), "utf8"));
const OUTDIR = path.join(ROOT, "out");
const FFMPEG = process.env.FFMPEG_EXE || process.env.FFMPEG || "ffmpeg";
const FFPROBE = process.env.FFPROBE || "ffprobe";

fs.mkdirSync(OUTDIR, { recursive: true });

// 大字卡 URL：4 版式轮换（layout = (轮次-1) % 4）
function cardUrl(seg) {
  const r = TL.rounds.find((x) => x.i === seg.round);
  const layout = (seg.round - 1) % 4;
  const first = r ? r.first : "还有";
  const keyword = r ? r.keyword : "更多？";
  const color = r ? r.color : "#ffcf5c";
  const q = new URLSearchParams({
    layout: String(layout), index: String(seg.round), total: "12",
    color, first, keyword, brand: TL.brand, theme: TL.theme,
  });
  return `/big-card.html?${q}`;
}

function styleUrl(seg) {
  const q = new URLSearchParams({ theme: TL.theme });
  return `${seg.page}?${q}`;
}

const only = process.argv.slice(2);
let totalFrames = 0;

for (const seg of TL.segments) {
  if (only.length && !only.includes(seg.id)) continue;
  const out = path.join(OUTDIR, `${seg.id}.mp4`);
  const page = seg.type === "card" ? cardUrl(seg) : styleUrl(seg);

  const args = [
    "render-segment.mjs", "--page", page, "--out", out,
    "--duration", String(seg.duration), "--t0", String(seg.t0), "--speed", String(seg.speed),
    // 上游默认 medium；实测 veryfast 在同 CRF 下编码耗时少 55%，画质差异不可见
    "--preset", "veryfast", "--crf", "17",
  ];
  const t0 = Date.now();
  const r = spawnSync("node", args, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
  const dt = ((Date.now() - t0) / 1000).toFixed(1);

  if (r.status !== 0) {
    console.error(`[FAIL] ${seg.id}  ${dt}s`);
    console.error((r.stderr || "").split("\n").slice(-8).join("\n"));
    process.exit(1);
  }

  // 帧数校验。用 flat 输出按键取值，避免 csv 列序随 ffprobe 版本变动
  const p = spawnSync(FFPROBE, ["-v", "error", "-select_streams", "v:0", "-count_frames",
    "-show_entries", "stream=nb_read_frames,width,height", "-of", "flat", out], { encoding: "utf8" });
  const grab = (k) => {
    const m = (p.stdout || "").match(new RegExp(`${k}="?(\\d+)"?`));
    return m ? parseInt(m[1], 10) : 0;
  };
  const frames = grab("nb_read_frames");
  const size = `${grab("width")}x${grab("height")}`;
  const expect = Math.round(seg.duration * TL.fps);
  const ok = frames === expect && size === `${TL.width}x${TL.height}`;
  totalFrames += frames;
  console.log(`${ok ? "[OK]  " : "[WARN]"} ${seg.id.padEnd(10)} ${frames}/${expect} 帧  ${size}  ${dt}s`);
  if (!ok) console.error(`       帧数或分辨率不符：期望 ${expect} 帧 ${TL.width}x${TL.height}`);
}

// segments.txt 按剪辑表顺序收录「已渲染」的段，支持分批渲染后直接 concat
const lines = [];
const missing = [];
for (const seg of TL.segments) {
  const out = path.join(OUTDIR, `${seg.id}.mp4`);
  if (fs.existsSync(out)) lines.push(`file '${out}'`);
  else missing.push(seg.id);
}
fs.writeFileSync(path.join(ROOT, "segments.txt"), lines.join("\n") + "\n");
console.log(`\n本批 ${totalFrames} 帧 → segments.txt 已写入 ${lines.length}/${TL.segments.length} 段`);
if (missing.length) {
  console.error(`未渲染：${missing.join(" ")}`);
  process.exit(1);
}
