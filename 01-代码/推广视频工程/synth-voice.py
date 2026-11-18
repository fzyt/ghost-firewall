#!/usr/bin/env python3
# synth-voice.py — 按旁白稿逐段合成语音，语速自动贴合各段时长。
#
# 唯一真相源是旁白稿 md（逐段引用行），改了稿子重跑这个脚本即可，不用改代码。
#
# 用法：
#   python3 synth-voice.py \
#     --script ../../03-文档/旁白稿-180s.md \
#     --out audio/voice \
#     --edge-tts /home/kirito/main/tmp/tts-venv/bin/edge-tts \
#     --voice zh-CN-YunxiNeural
#
# 产出：
#   audio/voice/s01.mp3 ... s09.mp3   逐段语音
#   audio/voice/manifest.json         每段的时长 / 语速 / 在全片里的起点
#
# 依赖 edge-tts（微软 Edge 在线 TTS，需要外网）。没有它就装一个：
#   uv venv /home/kirito/main/tmp/tts-venv && uv pip install --python <venv>/bin/python edge-tts
import argparse
import json
import os
import re
import subprocess
import sys

# 段内留白：旁白必须在段末之前收住，别压到下一段画面
TAIL_MARGIN = 0.8
# 语速上下限（edge-tts 允许正负）
RATE_MIN, RATE_MAX = -25, 40


def parse_script(path):
    """从旁白稿里抽出 9 段：段号、起点、时长、台词。"""
    src = open(path, encoding='utf-8').read()
    segs = []
    pat = re.compile(
        r'### (s\d\d)[^\n]*（(\d\d):(\d\d)–(\d\d):(\d\d)[^\n]*）\s*\n\s*\n((?:> .*\n)+)'
    )
    for m in pat.finditer(src):
        sid = m.group(1)
        t0 = int(m.group(2)) * 60 + int(m.group(3))
        t1 = int(m.group(4)) * 60 + int(m.group(5))
        text = ' '.join(line[2:].strip() for line in m.group(6).strip().split('\n'))
        segs.append({'id': sid, 'start': t0, 'duration': t1 - t0, 'text': text})
    if not segs:
        sys.exit(f'旁白稿里没解析出段落：{path}')
    return segs


def speech_duration(sub_path):
    """从字幕文件的最后一条 cue 取结束时间 —— 即语音实际长度（秒）。"""
    last = 0.0
    for line in open(sub_path, encoding='utf-8'):
        m = re.search(r'(\d\d):(\d\d):(\d\d)[.,](\d\d\d)\s*-->\s*(\d\d):(\d\d):(\d\d)[.,](\d\d\d)', line)
        if m:
            h, mi, s, ms, h2, mi2, s2, ms2 = (int(x) for x in m.groups())
            last = max(last, h2 * 3600 + mi2 * 60 + s2 + ms2 / 1000)
    return last


def synth(edge, voice, text, out_mp3, out_vtt, rate):
    # 用 --rate=... 等号形式：负值（如 -20%）才不会被 argparse 当成选项
    cmd = [edge, '--voice', voice, '--text', text, f'--rate={rate:+d}%',
           '--write-media', out_mp3, '--write-subtitles', out_vtt, '--no-progress']
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'edge-tts 失败：{r.stderr.strip()[-300:]}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--script', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--edge-tts', default='edge-tts')
    ap.add_argument('--voice', default='zh-CN-YunxiNeural')
    ap.add_argument('--total', type=float, default=180.0, help='全片时长（秒）')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    segs = parse_script(args.script)
    manifest = []

    for seg in segs:
        sid = seg['id']
        mp3 = os.path.join(args.out, f'{sid}.mp3')
        vtt = os.path.join(args.out, f'{sid}.vtt')
        target = seg['duration'] - TAIL_MARGIN

        # 先按自然语速合成一次，再按实际长度反推需要的语速
        rate = 0
        synth(args.edge_tts, args.voice, seg['text'], mp3, vtt, rate)
        dur = speech_duration(vtt)
        for _ in range(3):
            need = dur / target
            if abs(need - 1.0) < 0.03:
                break
            # 语速百分比 ≈ 需要的长度比例
            new_rate = int(round((need - 1.0) * 100))
            new_rate = max(RATE_MIN, min(RATE_MAX, new_rate))
            if new_rate == rate:
                break
            rate = new_rate
            synth(args.edge_tts, args.voice, seg['text'], mp3, vtt, rate)
            dur = speech_duration(vtt)

        over = dur - target
        flag = '超时' if over > 0.05 else ''
        print(f'{sid}  段长 {seg["duration"]:5.1f}s  语音 {dur:5.2f}s  语速 {rate:+d}%  {flag}')
        manifest.append({
            'id': sid, 'start': seg['start'], 'duration': seg['duration'],
            'speech': round(dur, 3), 'rate': rate, 'file': f'{sid}.mp3',
        })

    with open(os.path.join(args.out, 'manifest.json'), 'w', encoding='utf-8') as f:
        json.dump({'voice': args.voice, 'total': args.total, 'segments': manifest},
                  f, ensure_ascii=False, indent=2)
    print(f'\n清单写入 {os.path.join(args.out, "manifest.json")}')


if __name__ == '__main__':
    main()
