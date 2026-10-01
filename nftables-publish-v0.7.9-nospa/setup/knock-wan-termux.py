#!/usr/bin/env python3
# knock-wan-termux.py — nftables-web-v2 WAN 端口敲门内核（Termux / Android）
#
# 由 knock-wan-termux.sh 调用。本文件独立可执行（python3 knock-wan-termux.py）。
#
# 设计要点：
#   1. 严格遵循原 nftables 模板：4 步 UDP，每步 1 包，间隔 8s 内（脚本默认 1s）
#   2. UDP 无连接，sendto 失败不视为敲门失败（路由器可能 drop，但服务端仍匹配）
#   3. 数据伪装仅在 payload 上做手脚，包数严格保持 4 个（除噪音包外）
#   4. 噪音包只发到「非敲门端口」（WAN 模式由 shell 层剔除敲门端口；
#      Python 层再做一次兜底剔除，避免 shell 漏判）
#
# mode = lan | wan：
#   - lan: chain knock_lan（无 rate limit）
#   - wan: chain knock_wan_v4（rate limit 1/minute burst 1；
#          失败进 @error_ips4；多次失败进 blacklist4）
#
# 数据伪装实现：
#   - random   : 8~32 字节随机 payload
#   - ntp      : 构造 NTPv4 client (LI=0,VN=4,Mode=3), 48 字节
#   - dns      : 构造最小 DNS 查询（ping.home.arpa. IN AAAA）
#   - tls      : 构造最小 TLS 1.2 ClientHello（SNI=www.microsoft.com）
#   - stun     : 构造 STUN Binding Request（带 RFC 5389 magic cookie）
#   - wireguard: 构造 WG handshake initiation 第 1 字节（type=1, sender=随机）
#   - none     : 默认 payload b'k'
#
# 噪音包：
#   按 --noise N 在每步之间均匀插入 N 个 UDP 包到 NOISE_PORTS 中的端口
#   payload 与 mimic 模式一致（除了 wireguard 用 random，避免 5 次 WG init 看起来异常）

import os
import socket
import struct
import sys
import time
import secrets
import random


def getenv(name: str, default: str = "") -> str:
    val = os.environ.get(name, default)
    return val if val else default


def make_payload(mimic: str) -> bytes:
    """根据 mimic 模式构造 payload。"""
    if mimic == "none":
        return b"k"

    if mimic == "random" or mimic == "noise":
        n = random.randint(8, 32)
        return secrets.token_bytes(n)

    if mimic == "ntp":
        # NTP v4 client request
        # LI(2) | VN(3) | Mode(3) | Stratum(8) | Poll(8) | Precision(8) |
        # RootDelay(32) | RootDispersion(32) | ReferenceID(32) | ReferenceTS(64) |
        # OriginTS(64) | ReceiveTS(64) | TransmitTS(64)
        # Client mode: 0 100 011 = 0x23
        # Stratum=0 (unspecified), Poll=4, Precision=0xFA (-6)
        # NTP header: LI|VN|Mode(1) + Stratum(1) + Poll(1) + Precision(1, signed byte 2^-6)
        #             + RootDelay(4) + RootDisp(4) + RefID(4) + RefTS(8)
        #             + OrigTS(8) + RecvTS(8) + TransTS(8) = 48 bytes total
        pkt = struct.pack(
            "!BBBB",          # 4B: flags + stratum + poll + precision(unsigned 0xFA = -6 signed)
            0x23, 0, 4, 0xFA,
        ) + struct.pack(
            "!3I",            # 12B: RootDelay, RootDisp, RefID
            0, 0, 0,
        ) + struct.pack(
            "!4Q",            # 32B: RefTS, OrigTS, RecvTS, TransTS
            0, 0, 0, 0,
        )
        assert len(pkt) == 48, f"NTP 包长度异常: {len(pkt)}"
        return pkt

    if mimic == "dns":
        # 构造一个最小 DNS 查询：ping.home.arpa. IN AAAA
        # Header: ID=0x1234, QR=0, OPCODE=0, RD=1, QDCOUNT=1
        qname = b"\x04ping\x04home\x05arpa\x00"  # ping.home.arpa.
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        question = qname + struct.pack("!HH", 28, 1)  # AAAA=28, IN=1
        return header + question

    if mimic == "tls":
        # 构造一个最小 TLS 1.2 ClientHello
        # 这里只拼出一个骨架，长度足以让抓包看到 ClientHello 指纹特征
        # SNI: www.microsoft.com
        sni = b"www.microsoft.com"
        # ServerName extension
        sni_list = struct.pack("!BH", 0, len(sni)) + sni  # name_type=0 (host_name)
        sni_ext = struct.pack("!HH", 0, len(sni_list) + 2) + struct.pack("!H", len(sni_list)) + sni_list

        # Supported Versions extension (假装支持 TLS 1.3)
        sv_data = struct.pack("!B", 2) + struct.pack("!H", 0x0304)  # TLS 1.3
        sv_ext = struct.pack("!HH", 0x002b, len(sv_data)) + sv_data

        # Signature Algorithms extension
        sig_data = struct.pack("!H", 4) + struct.pack("!HH", 0x0401, 0x0501)  # rsa_pkcs1_sha256/384
        sig_ext = struct.pack("!HH", 0x000d, len(sig_data)) + sig_data

        extensions = sni_ext + sv_ext + sig_ext
        extensions_field = struct.pack("!H", len(extensions)) + extensions

        # Random (32 bytes)
        random_bytes = secrets.token_bytes(32)

        # SessionID (1 字节长度 + 0 字节)
        session_id = b"\x00"
        # Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301)
        cipher_suites = struct.pack("!HH", 2, 0x1301)
        # Compression: null
        compression = struct.pack("!BB", 1, 0)

        # ClientHello body（不含 record 层）
        body = (
            struct.pack("!BB", 3, 3)            # version: TLS 1.2
            + random_bytes
            + session_id
            + cipher_suites
            + compression
            + extensions_field
        )
        handshake = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body  # type=1 (ClientHello), length(3 bytes)
        # TLS Record: type=22 (Handshake), version=0x0301 (TLS 1.0 record layer), length
        record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake
        return record

    if mimic == "stun":
        # STUN Binding Request (RFC 5389)
        # Type=0x0001, Length=0, Magic Cookie=0x2112A442, TransactionID=12 bytes
        return struct.pack("!HHI", 0x0001, 0, 0x2112A442) + secrets.token_bytes(12)

    if mimic == "wireguard":
        # WireGuard handshake initiation 第 1 字节 type=1, 后面 3 字节 reserved=0,
        # 然后 4 字节 sender index
        return struct.pack("!BBI", 1, 0, random.randint(1, 0xFFFFFF)) + secrets.token_bytes(32)

    # fallback
    return b"k"


def send_udp(host: str, port: int, payload: bytes, timeout: float = 2.0) -> bool:
    """发送单个 UDP 包。返回 True=本机 socket 成功送出（不保证路由器收到）。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (host, port))
        return True
    except OSError as e:
        print(f"[Knock]   sendto {host}:{port} 失败: {e}", file=sys.stderr)
        return False


def main() -> int:
    host = getenv("HOST", "127.0.0.1")
    ports_s = getenv("PORTS", "")
    interval = float(getenv("INTERVAL", "1"))
    jitter = float(getenv("JITTER", "0"))
    mimic = getenv("MIMIC", "none")
    noise_n = int(getenv("NOISE", "0"))
    noise_ports_s = getenv("NOISE_PORTS", "53,123,443,3478,51820")
    dry_run = getenv("DRY_RUN", "0") == "1"
    quiet = getenv("QUIET", "0") == "1"
    mode = getenv("MODE", "wan").lower()

    try:
        ports = [int(p.strip()) for p in ports_s.split(",") if p.strip()]
    except ValueError:
        print("ERROR: PORTS 解析失败: " + ports_s, file=sys.stderr)
        return 1

    if len(ports) != 4:
        print(f"ERROR: 必须 4 个端口，实际 {len(ports)}: {ports_s}", file=sys.stderr)
        return 1

    try:
        noise_ports = [int(p.strip()) for p in noise_ports_s.split(",") if p.strip()]
    except ValueError:
        noise_ports = [53, 123, 443, 3478, 51820]

    # WAN 兜底：剔除噪音端口中与敲门端口重叠的部分
    # （shell 层已剔除过；这里再保一次防御）
    if mode == "wan":
        noise_ports = [p for p in noise_ports if p not in ports]
        if not noise_ports and noise_n > 0:
            print("[Knock] WARN: 噪音目标端口全部与敲门端口重叠，噪音禁用", file=sys.stderr)
            noise_n = 0

    def log(msg: str) -> None:
        if not quiet:
            print(msg)

    log(f"[Knock] Python 内核: mode={mode}  mimic={mimic}  noise={noise_n}")

    # 预生成每个 step 的 payload（用同一个 payload 跨所有 step 也能工作；
    # 但服务端只看 udp dport，不看 payload，所以随机 payload 反而更隐蔽）
    payloads = [make_payload(mimic) for _ in range(4)]

    # 噪音 payload：mimic=wireguard 时用 random，避免重复 WG init 太假
    noise_mimic = "random" if mimic == "wireguard" else mimic
    noise_payload = make_payload(noise_mimic) if noise_n > 0 else b""

    total_send = 0
    total_fail = 0

    for i, port in enumerate(ports, start=1):
        log(f"[Knock] step {i}/4 -> {host}:{port}  payload[{len(payloads[i-1])}B]")

        # 在敲门前先发噪音包到其他端口（让路由器日志看起来"先有探活，再敲门"）
        if noise_n > 0 and i > 1 and noise_ports:
            for k in range(noise_n):
                # 从 noise_ports 里选一个与本 step port 不同的端口
                candidates = [p for p in noise_ports if p != port]
                if not candidates:
                    # WAN 模式绝对不能 fallback 回 noise_ports（可能含敲门端口 → @error_ips）
                    # LAN 模式无 @error_ips，可以 fallback
                    if mode == "wan":
                        log(f"[Knock]   [skip noise] step {i} port={port} 无候选，跳过噪音")
                        continue
                    candidates = noise_ports
                np = random.choice(candidates)
                if dry_run:
                    log(f"[Knock]   [dry] noise {host}:{np}")
                else:
                    ok = send_udp(host, np, noise_payload)
                    total_send += 1
                    if not ok:
                        total_fail += 1
                # 噪音包之间的小间隔
                time.sleep(0.1 + random.random() * 0.2)

        # 真正敲门
        if dry_run:
            log(f"[Knock]   [dry] knock {host}:{port}  payload={payloads[i-1].hex()[:32]}...")
        else:
            ok = send_udp(host, port, payloads[i-1])
            total_send += 1
            if not ok:
                total_fail += 1

        # 步间 jitter
        if i < 4:
            delay = interval
            if jitter > 0:
                delay = interval + random.uniform(-jitter, jitter)
                if delay < 0.1:
                    delay = 0.1
            log(f"[Knock]   等待 {delay:.2f}s")
            time.sleep(delay)

    log(f"[Knock] 完成：发送 {total_send} 包，失败 {total_fail} 包")

    if total_fail > 0:
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[Knock] 用户中断", file=sys.stderr)
        sys.exit(130)
