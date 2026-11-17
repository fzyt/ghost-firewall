#!/usr/bin/env bash
# qc.sh — 成片质检：接触表 / 频谱 / 封面 / 帧数 / 卡点对齐
#
#   ./qc.sh [成片.mp4] [输出目录]
#
# 依赖：ffmpeg、ffprobe（环境变量 FFMPEG/FFPROBE）、python3 + numpy
set -euo pipefail

VIDEO="${1:-out/final.mp4}"
OUTDIR="${2:-../../05-媒体}"
FFMPEG="${FFMPEG:-ffmpeg}"
FFPROBE="${FFPROBE:-ffprobe}"
PYTHON="${PYTHON:-python3}"

mkdir -p "$OUTDIR"
STEM="$(basename "${VIDEO%.*}")"

# 接触表步长与封面帧按成片长度算：61 秒片的写死值套到 180 秒片上会溢出格子
DUR="$("$FFPROBE" -v error -show_entries format=duration -of csv=p=0 "$VIDEO")"
FPS_N="$("$FFPROBE" -v error -select_streams v:0 -show_entries stream=r_frame_rate -of csv=p=0 "$VIDEO" | awk -F/ '{printf "%d", $1}')"
STEP=$(( FPS_N * 6 ))                       # 每 6 秒取一帧
CELLS=$(( ${DUR%.*} / 6 + 1 ))
COLS=8
ROWS=$(( (CELLS + COLS - 1) / COLS ))
COVER_T="${COVER_T:-$(awk "BEGIN { printf \"%.1f\", $DUR * 0.135 }")}"   # 默认取 13.5% 处

echo "== 1/5 帧数 / 分辨率 / 时长 =="
"$FFPROBE" -v error -count_frames -select_streams v:0 \
  -show_entries stream=nb_read_frames,width,height,r_frame_rate \
  -show_entries format=duration,size -of default=nw=1 "$VIDEO"

echo "== 2/5 接触表（每 6 秒一帧，${COLS}x${ROWS} = ${COLS}x${ROWS} 格）=="
"$FFMPEG" -y -hide_banner -loglevel error -i "$VIDEO" \
  -vf "select='not(mod(n,${STEP}))',scale=320:-1,tile=${COLS}x${ROWS}" \
  -fps_mode passthrough -frames:v 1 "$OUTDIR/接触表-${STEM}.jpg"
echo "   -> $OUTDIR/接触表-${STEM}.jpg"

echo "== 3/5 音频频谱 =="
"$FFMPEG" -y -hide_banner -loglevel error -i "$VIDEO" \
  -lavfi "showspectrumpic=s=1920x1080:legend=1" -frames:v 1 "$OUTDIR/频谱-${STEM}.png"
echo "   -> $OUTDIR/频谱-${STEM}.png"

echo "== 4/5 封面帧（${COVER_T}s）=="
"$FFMPEG" -y -hide_banner -loglevel error -ss "$COVER_T" -i "$VIDEO" \
  -frames:v 1 -q:v 2 "$OUTDIR/封面-${STEM}.jpg"
echo "   -> $OUTDIR/封面-${STEM}.jpg"

echo "== 5/5 卡点对齐（音频起音是否落在八分网格；拍点网格作参照）=="
"$PYTHON" - "$VIDEO" <<'PY'
import sys, subprocess, numpy as np

path = sys.argv[1]
raw = subprocess.run(
    ["ffmpeg", "-v", "error", "-i", path, "-ac", "1", "-ar", "48000",
     "-f", "f32le", "-"], capture_output=True, check=True).stdout
x = np.frombuffer(raw, dtype=np.float32)

SR = 48000
HOP = 256
n = len(x) // HOP
w = np.hanning(HOP)
frames = np.lib.stride_tricks.as_strided(
    x, shape=(n, HOP), strides=(x.strides[0] * HOP, x.strides[0]))
spec = np.abs(np.fft.rfft(frames * w, axis=1))
# 半波整流的谱通量 = 逐帧起音强度
flux = np.maximum(0, np.diff(spec, axis=0)).sum(axis=1)
flux = flux / (flux.max() or 1)

PEAK = 0.35          # 相对阈值，滤掉密集的鼓点泛音
MIN_GAP = 0.18       # 秒，两个起音的最小间隔
onsets, last = [], -1e9
for i, v in enumerate(flux):
    t = i * HOP / SR
    if v > PEAK and t - last > MIN_GAP:
        onsets.append(t)
        last = t

# 拍点：120 BPM → 一拍 0.5s；八分音符网格 0.25s。
# 用哪套网格取决于配乐用了哪层节奏：本片有八分音符开镲（在反拍 +0.25），
# 所以起音应当对齐八分网格 —— 只按 0.5s 拍点判会把八分镲误判成错位。
# 两个数字都打出来，拍点网格那个是参照，不是判据。
BEAT = 0.5
EIGHTH = BEAT / 2

def grid_off(times, grid):
    d = np.array([t % grid for t in times])
    return np.minimum(d, grid - d)

off8 = grid_off(onsets, EIGHTH)
off4 = grid_off(onsets, BEAT)
aligned8 = (off8 < 0.03).mean() if len(onsets) else 0.0
aligned4 = (off4 < 0.03).mean() if len(onsets) else 0.0
print(f"   起音数 {len(onsets)}")
print(f"   对八分网格({EIGHTH}s)：偏差中位数 {np.median(off8)*1000:.1f} ms，"
      f"落在 ±30ms 比例 {aligned8*100:.1f}%")
print(f"   对拍点网格({BEAT}s)（参照）：偏差中位数 {np.median(off4)*1000:.1f} ms，"
      f"落在 ±30ms 比例 {aligned4*100:.1f}%")
print(f"   偏差最大的 5 个: {', '.join(f'{o*1000:.0f}ms' for o in np.sort(off8)[-5:])}")
sys.exit(0 if aligned8 >= 0.8 else 1)
PY
echo "   质检完成"
