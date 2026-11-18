#!/usr/bin/env python3
# mix-voice.py — 旁白按段落到全片时间轴，与配乐闪避（ducking）混成一条音轨。
#
# 用法（在渲染主机上跑，需要 ffmpeg）：
#   python3 mix-voice.py --manifest audio/voice/manifest.json \
#     --voice-dir audio/voice --music audio/score-180s.wav --out audio/mix-voice-180s.wav
#
# 产出是一条 48k 立体声 wav，直接喂给 concat-and-encode.sh 当音轨。
import argparse
import json
import os
import shutil
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--voice-dir', required=True)
    ap.add_argument('--music', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--ffmpeg', default=os.environ.get('FFMPEG', 'ffmpeg'))
    args = ap.parse_args()

    man = json.load(open(args.manifest, encoding='utf-8'))
    segs = man['segments']
    total = man['total']

    cmd = [args.ffmpeg, '-y', '-hide_banner', '-loglevel', 'error']
    for s in segs:
        cmd += ['-i', os.path.join(args.voice_dir, s['file'])]
    music_idx = len(segs)
    cmd += ['-i', args.music]

    # 每段旁白先统一格式，再按它在全片里的起点延迟到位
    parts = []
    for i, s in enumerate(segs):
        ms = int(round(s['start'] * 1000))
        parts.append(
            f'[{i}]aformat=sample_fmts=fltp:sample_rates=48000:channel_layouts=stereo,'
            f'adelay={ms}:all=1[v{i}]'
        )
    voices = ''.join(f'[v{i}]' for i in range(len(segs)))
    fc = ';'.join(parts)
    # 旁白混成一条 → 补静音到全片长 → 统一响度（人声标准 -16 LUFS）
    fc += f';{voices}amix=inputs={len(segs)}:normalize=0:duration=longest'
    fc += f',apad,atrim=0:{total},loudnorm=I=-16:TP=-1.5:LRA=11'
    # 一条旁白要用两次（侧链触发 + 最终混合），ffmpeg 里必须先 asplit
    fc += ',asplit=2[voiceA][voiceB]'
    # 配乐被旁白当侧链触发，静音期自动恢复
    fc += f';[{music_idx}]aformat=sample_fmts=fltp:sample_rates=48000:channel_layouts=stereo[music]'
    fc += ';[music][voiceA]sidechaincompress=threshold=0.02:ratio=8:attack=12:release=320[duck]'
    fc += ';[duck][voiceB]amix=inputs=2:normalize=0,alimiter=limit=0.95[out]'

    cmd += ['-filter_complex', fc, '-map', '[out]', '-ac', '2', '-ar', '48000',
            '-t', str(total), args.out]
    print(' '.join(cmd[:6]), '...')
    r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit('ffmpeg 混音失败')
    print(f'混音完成：{args.out}（{os.path.getsize(args.out)} 字节）')


if __name__ == '__main__':
    main()
