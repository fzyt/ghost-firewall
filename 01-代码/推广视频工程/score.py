#!/usr/bin/env python3
"""180 秒产品讲解片配乐 —— 按 timeline.json 的分段编排，复用 synth_audio.py 音色库。

结构（120 BPM，1 拍 0.5s，1 小节 2s，90 小节）：
  0-21    问题    暗：低 pad + 稀疏 sub boom + 打字 tick
  21-36   架构    稳：军鼓 4 分 + 轻 hat + pad
  36-61   敲门    核心：4 音动机（对应真实的 4 步 UDP 敲门协议），每小节一组
  61-87   安全    重：完整鼓组 + 逐级升高的低频脉冲（三级惩罚）
  87-105  网关    流动：八分琶音 + bell
  105-121 认证    心跳：强弱 kick + 稀疏 bell
  121-142 功能    密：快速琶音 + 稳定 4/4
  142-160 安装    简洁：干净 2 拍 + 上行 riser
  160-180 收尾    宏大：全奏 + 176s impact + 淡出

高频克制：金属铃音只在 87s（网关揭示）、121s（功能揭示）、176s（结尾 impact）三处。
"""
import argparse
import os
import sys
import wave
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from synth_audio import (  # noqa: E402
    SR, BPM, CHORDS, CHORD_TABLE,
    t_axis, place, lowpass, highpass, bandpass, adsr, exp_decay, noise, note_freq,
    kick, snare, clap, hat, crash, sub_boom, riser, reverse_crash, whoosh,
    pluck, epiano, bell, supersaw, square_lead, triangle_lead, eight08, flute,
    make_ir, reverb_stereo, kick_sidechain, master,
)

BEAT = 60.0 / BPM          # 0.5s
BAR = 4 * BEAT             # 2.0s
DUR = 180.0

# 与 timeline.json 的 segments 对齐（start, end, 音量权重）
SECTIONS = [
    (0.0, 21.0, 0.45),      # 问题
    (21.0, 36.0, 0.72),     # 架构
    (36.0, 61.0, 0.85),     # 敲门
    (61.0, 87.0, 1.00),     # 安全
    (87.0, 105.0, 0.80),    # 网关
    (105.0, 121.0, 0.82),   # 认证
    (121.0, 142.0, 0.88),   # 功能
    (142.0, 160.0, 0.75),   # 安装
    (160.0, 180.0, 0.95),   # 收尾
]

# 敲门动机的 4 个音 —— 对应真实的 4 步 UDP 协议，音高逐级上行
KNOCK_MOTIF = ["A3", "C4", "E4", "G4"]


def music_gain(t: float) -> float:
    """段落权重 + 边界 0.6 秒交叉淡化。"""
    g = 0.45
    for i, (s, e, w) in enumerate(SECTIONS):
        if s <= t < e:
            g = w
            fade = 0.6
            if t < s + fade and i > 0:
                prev = SECTIONS[i - 1][2]
                g = prev + (w - prev) * (t - s) / fade
            elif e - t < fade and i + 1 < len(SECTIONS):
                nxt = SECTIONS[i + 1][2]
                g = w + (nxt - w) * (1 - (e - t) / fade)
            break
    return g


def pad(freqs, dur: float) -> np.ndarray:
    t = t_axis(dur)
    p = sum(np.sin(2 * np.pi * f * t) for f in freqs) / max(len(freqs), 1)
    p = lowpass(p, 1600)
    return p * adsr(len(t), 0.12, 0.3, 0.75, 0.35)


def place_pad(buf, freqs, start, dur, gain):
    """按 0.1s 切片放置，让段落淡变也能作用到 pad 内部。"""
    step = 0.1
    t = start
    while t < start + dur:
        seg = min(step, start + dur - t)
        g = gain * music_gain(t + seg / 2)
        if g > 0.002:
            place(buf, pad(freqs, seg + 0.2), t, g)
        t += step


def place_melody(buf, sample, start, gain):
    """旋律音色的统一落点（sample 已算好，这里只管音量与定位）。"""
    g = gain * music_gain(start)
    if g > 0.002:
        place(buf, sample, start, g)


# ---------------------------------------------------------------- 各段编排
def sec_problem(music, drums, fx, t0, chord, roots):
    """0-14 暗：低音 pad + 稀疏低频脉冲 + 打字 tick。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.11)
    place(fx, sub_boom(0.9), t0, 0.45)
    place(fx, sub_boom(0.9), t0 + 2 * BEAT, 0.30)
    # 打字 tick：细小的高频咔哒
    for k in range(8):
        tb = t0 + k * BEAT / 2
        if tb >= t0 + 2.0 and tb < t0 + 8.0:
            click = noise(int(0.02 * SR), seed=300 + k) * exp_decay(t_axis(0.02), 160)
            place(fx, highpass(click, 3000), tb, 0.09)


def sec_arch(music, drums, fx, t0, chord, roots):
    """14-30 稳：军鼓 4 分音符 + 轻 hat + pad。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.13)
    place_pad(music, [note_freq(x) for x in CHORDS[chord[1]]], t0 + 2 * BEAT, 2.0, 0.10)
    for b in range(4):
        tb = t0 + b * BEAT
        if b % 2 == 0:
            place(drums, kick(), tb, 0.70)
            place(drums, snare(0.18, seed=44), tb, 0.18)
        else:
            place(drums, hat(), tb, 0.11)
    place(fx, reverse_crash(1.0), t0, 0.16)


def sec_knock(music, drums, fx, t0, chord, roots):
    """30-52 敲门：4 音动机每小节一组 + 稳定的 8 分 hat。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.08)
    place_pad(music, [note_freq(x) for x in CHORDS[chord[1]]], t0 + 2 * BEAT, 2.0, 0.06)
    # 四步敲门：每拍一声，音高按 KNOCK_MOTIF 逐级上行
    for k in range(4):
        tb = t0 + k * BEAT
        f = note_freq(KNOCK_MOTIF[k])
        place_melody(music, pluck(f, 0.30, harmonics=6, decay=14), tb, 0.30)
        # UDP 包的瞬态：极短的高频噪声
        pkt = noise(int(0.015 * SR), seed=410 + k) * exp_decay(t_axis(0.015), 220)
        place(fx, highpass(pkt, 4500), tb, 0.13)
    # 底鼓只落在小节首拍，给动机让位
    place(drums, kick(0.5, 48, 180, 8), t0, 0.62)
    for b in range(4):
        place(drums, hat(open_=True), t0 + b * BEAT + BEAT / 2, 0.07)


def sec_security(music, drums, fx, t0, chord, roots):
    """52-78 安全：完整鼓组 + 逐级升高的低频脉冲。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.11)
    place_pad(music, [note_freq(x) for x in CHORDS[chord[1]]], t0 + 2 * BEAT, 2.0, 0.09)
    for b in range(4):
        tb = t0 + b * BEAT
        if b == 0:
            place(drums, kick(), tb, 0.95)
            place(drums, clap(), tb, 0.30)
            place(fx, crash(1.6), tb, 0.20)
            place(fx, sub_boom(0.8), tb, 0.70)      # 第一级惩罚
        elif b in (1, 3):
            place(drums, kick(0.4, 52, 200, 9), tb, 0.72)
            place(drums, clap(), tb, 0.26)
            place(fx, sub_boom(0.5), tb, 0.40)      # 第二级
        else:
            place(drums, snare(), tb, 0.22)
            place(fx, sub_boom(0.35), tb, 0.26)     # 第三级
        place(drums, hat(), tb, 0.13)
        place(drums, hat(open_=True), tb + BEAT / 2, 0.08)
    # 一记长脉冲压在第 2 小节，强化「惩罚升级」
    place(fx, sub_boom(1.2), t0 + 2 * BAR, 0.55)


def sec_gateway(music, drums, fx, t0, chord, roots):
    """78-98 网关：八分琶音流动 + 轻鼓。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.14)
    place_pad(music, [note_freq(x) for x in CHORDS[chord[1]]], t0 + 2 * BEAT, 2.0, 0.12)
    notes = CHORDS[chord[0]] + CHORDS[chord[1]]
    for k in range(8):
        tb = t0 + k * BEAT / 2
        f = note_freq(notes[k % len(notes)])
        place_melody(music, epiano(f, 0.24, index=1.3), tb, 0.17)
    place(drums, kick(), t0, 0.70)
    place(drums, kick(), t0 + 2 * BEAT, 0.62)
    place(drums, snare(0.18, seed=44), t0 + 2 * BEAT, 0.20)
    for b in range(4):
        place(drums, hat(), t0 + b * BEAT, 0.10)
    place(fx, bell(note_freq("A5"), 1.4), t0, 0.14)   # 段落揭示点


def sec_auth(music, drums, fx, t0, chord, roots):
    """98-120 认证：心跳式强弱 kick + 稀疏提示音。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.12)
    place_pad(music, [note_freq(x) for x in CHORDS[chord[1]]], t0 + 2 * BEAT, 2.0, 0.10)
    for b in range(4):
        tb = t0 + b * BEAT
        # 心跳：强-弱-强-弱
        if b in (0, 2):
            place(drums, kick(0.5, 46, 170, 7), tb, 0.88)
            place(drums, kick(0.3, 44, 120, 12), tb + 0.14, 0.34)
        else:
            place(drums, hat(), tb, 0.09)
        if b == 2:
            place(drums, clap(), tb, 0.22)
    # 令牌提示音：每小节一个，间隔 1.5 秒 —— 呼应「滑动续期」
    place_melody(music, triangle_lead(note_freq("E5"), 0.22), t0, 0.16)
    place_melody(music, triangle_lead(note_freq("E5"), 0.22), t0 + 1.5, 0.13)


def sec_features(music, drums, fx, t0, chord, roots):
    """120-148 功能：快速琶音 + 稳定 4/4，信息密度高。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.10)
    place_pad(music, [note_freq(x) for x in CHORDS[chord[1]]], t0 + 2 * BEAT, 2.0, 0.09)
    notes = CHORDS[chord[0]] + CHORDS[chord[1]]
    for k in range(16):
        tb = t0 + k * BEAT / 4
        f = note_freq(notes[(k * 3) % len(notes)])
        place_melody(music, pluck(f, 0.20, harmonics=5, decay=18), tb, 0.13)
    for b in range(4):
        tb = t0 + b * BEAT
        place(drums, kick(), tb, 0.78 if b % 2 == 0 else 0.58)
        if b in (1, 3):
            place(drums, clap(), tb, 0.24)
        place(drums, hat(), tb, 0.11)
        place(drums, hat(open_=True), tb + BEAT / 2, 0.07)
    if abs(t0 - 121.0) < 0.01:
        place(fx, bell(note_freq("C6"), 1.4), t0, 0.16)   # 段落揭示点


def sec_install(music, drums, fx, t0, chord, roots):
    """148-162 安装：干净的两拍 + 尾部上行 riser。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.12)
    for b in range(4):
        tb = t0 + b * BEAT
        place(drums, kick(), tb, 0.66)
        place(drums, hat(), tb, 0.10)
        if b == 2:
            place(drums, clap(), tb, 0.22)
    # 干净的短音，像敲回车
    place_melody(music, epiano(note_freq("C5"), 0.18, index=1.1), t0, 0.16)


def sec_end(music, drums, fx, t0, chord, roots):
    """162-180 收尾：全奏 + 176s impact + 淡出。"""
    place_pad(music, [note_freq(x) for x in CHORDS[chord[0]]], t0, 2.0, 0.17)
    place_pad(music, [note_freq(x) for x in CHORDS[chord[1]]], t0 + 2 * BEAT, 2.0, 0.15)
    notes = CHORDS[chord[0]] + CHORDS[chord[1]]
    for b in range(4):
        tb = t0 + b * BEAT
        place(drums, kick(), tb, 0.95)
        if b in (1, 3):
            place(drums, clap(), tb, 0.30)
            place(drums, snare(), tb, 0.22)
        place(drums, hat(), tb, 0.14)
        place(drums, hat(open_=True), tb + BEAT / 2, 0.09)
        f = note_freq(notes[(b * 2) % len(notes)])
        place_melody(music, supersaw(f, 0.5, voices=5, detune=0.12), tb, 0.15)
    # 倒数 8 秒推起来
    place(fx, riser(3.0, seed=9), 173.0, 0.30)
    # 结尾 impact
    place(fx, crash(2.2), 176.0, 0.42)
    place(fx, sub_boom(1.4), 176.0, 0.85)
    place(drums, kick(0.8, 42, 150, 6), 176.0, 1.0)
    place(drums, clap(), 176.0, 0.40)
    place(fx, bell(note_freq("A5"), 2.0), 176.0, 0.22)


def build() -> np.ndarray:
    music = np.zeros(int(DUR * SR) + SR, dtype=np.float64)
    drums = np.zeros_like(music)
    fx = np.zeros_like(music)

    n_bars = int(round(DUR / BAR))          # 90 小节
    for i in range(n_bars):
        t0 = i * BAR
        chord = CHORD_TABLE[i % len(CHORD_TABLE)]
        if t0 < 21.0:
            sec_problem(music, drums, fx, t0, chord, None)
        elif t0 < 36.0:
            sec_arch(music, drums, fx, t0, chord, None)
        elif t0 < 61.0:
            sec_knock(music, drums, fx, t0, chord, None)
        elif t0 < 87.0:
            sec_security(music, drums, fx, t0, chord, None)
        elif t0 < 105.0:
            sec_gateway(music, drums, fx, t0, chord, None)
        elif t0 < 121.0:
            sec_auth(music, drums, fx, t0, chord, None)
        elif t0 < 142.0:
            sec_features(music, drums, fx, t0, chord, None)
        elif t0 < 160.0:
            sec_install(music, drums, fx, t0, chord, None)
        else:
            sec_end(music, drums, fx, t0, chord, None)

    # 段落的分界处加一个反向镲做「换气」
    for _, t in [(21.0, 21.0), (36.0, 36.0), (61.0, 61.0), (87.0, 87.0),
                 (105.0, 105.0), (121.0, 121.0), (142.0, 142.0), (160.0, 160.0)]:
        place(fx, reverse_crash(1.0), t - 0.5, 0.20)

    # 混音
    x = music * 0.9 + drums * 0.85 + fx * 0.55

    # 侧链：让 kick 压住其它声部（kick_sidechain 第一个参数是长度，不是音频）
    kicks = [i * BAR for i in range(n_bars)]
    kicks += [b * BAR + 2 * BEAT for b in range(n_bars) if b * BAR + 2 * BEAT < DUR]
    kicks += [176.0]
    x = x * kick_sidechain(len(x), kicks, 0.42)

    # 空间
    ir = make_ir(2.4, seed=77)
    x = reverb_stereo(x, ir, wet=0.18)

    # 结尾淡出（reverb_stereo 之后是 (2, N) 立体声）
    x = x[:, :int(DUR * SR)]
    fade = int(3.0 * SR)
    x[:, -fade:] *= np.linspace(1.0, 0.0, fade)

    return master(x, peak_db=-1.2, drive=1.15)


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 180 秒产品讲解片配乐")
    ap.add_argument("--out", default="audio/score-180s.wav")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    x = build()

    peak = float(np.max(np.abs(x)))
    rms = float(np.sqrt(np.mean(x ** 2)))
    print(f"时长 {x.shape[-1]/SR:.3f}s  峰值 {peak:.4f} ({20*np.log10(peak+1e-12):.2f} dBFS)  "
          f"RMS {20*np.log10(rms+1e-12):.2f} dBFS")

    # 用标准库 wave 写盘：scipy 1.17 的 wavfile.write 在大数组上会抛
    # "ushort format requires 0 <= number <= 65535"（34MB 立体声即触发）
    with wave.open(str(out), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes((x * 32767).astype(np.int16).tobytes())
    print(f"已写入 {out}（{out.stat().st_size/1048576:.2f} MB）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
