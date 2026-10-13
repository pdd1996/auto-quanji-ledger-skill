# -*- coding: utf-8 -*-
"""
银行流水 PDF 设备端口令恢复（unlock）—— 处理"加密且只读"的官方明细 PDF。

适用：标准安全处理器 Revision 2 / 3（RC4 40/128 位）——工行/建行等的
"历史明细打印"导出的 PDF 目前多为 Rev3 RC4-128；口令为短数字时可在本机秒级恢复。
不适用：AES（R5/R6）加密的 PDF —— 无快速捷径，会明确拒绝。

硬边界（与 references/privacy.md 一致）：
  * 必须用户显式给出 --consent 才进入恢复模式，开始前打印代价说明。
  * 恢复出的口令默认只写本地文件（明文，有警告），不打印；--show 供本地终端自看。
  * 全程仅在本机；口令不进入对话/日志/远端。

用法：
    python scripts/unlock_pdf.py probe  "明细.pdf"
    python scripts/unlock_pdf.py recover "明细.pdf" --consent
    python scripts/unlock_pdf.py recover "明细.pdf" --consent --out-dir <目录>
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import multiprocessing as mp
import os
import struct
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

WORK = os.environ.get("BILL_WORK") or os.path.join(os.path.expanduser("~"), ".bill-lens")
PWD_SAVE = os.path.join(WORK, "recovered_pwds.local.txt")

_PADDING = bytes([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
    0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
])

COST_NOTICE = """\
────────────────────────────────────────────────────────────
代价说明（继续即视为你明确要求在本设备上进行口令恢复）
  * 法律：处置你本人的文件，不构成"未经授权访问系统"；
  * 平台：银行对账单 PDF 的只读加密属平台设定，恢复口令可能触及协议条款；
  * 上架：内置恢复逻辑是应用商店审核风险点，对外分发前请评估；
  * 收益：通常只是省掉一次在 App 订单详情里看一眼口令。
  约束：全程仅在本机进行；口令不打印、不进对话、不上传。
────────────────────────────────────────────────────────────"""


# ── R2/R3 校验核心（对照 ISO 32000-1 Algorithm 2/5/6，与 pypdf 行为一致）──
def _pad(pw: bytes) -> bytes:
    return (pw + _PADDING)[:32]


def _rc4(key: bytes, data: bytes) -> bytes:
    from Crypto.Cipher import ARC4
    return ARC4.new(key).encrypt(data)


def _user_key(pw: bytes, o: bytes, p_unsigned: int, id0: bytes, n: int, rev: int) -> bytes:
    h = hashlib.md5(_pad(pw) + o + struct.pack("<I", p_unsigned) + id0).digest()
    if rev >= 3:
        for _ in range(50):
            h = hashlib.md5(h[:n]).digest()
    return h[:n]


def verify_user(pw: bytes, params) -> bool:
    o, u, p_unsigned, id0, n, rev = params
    key = _user_key(pw, o, p_unsigned, id0, n, rev)
    if rev <= 2:
        return _rc4(key, _PADDING) == u[:32]
    r = _rc4(key, hashlib.md5(_PADDING + id0).digest())
    for i in range(1, 20):
        r = _rc4(bytes(b ^ i for b in key), r)
    return r[:16] == u[:16]


def _as_bytes(v) -> bytes:
    """pypdf 可能把二进制串解析为 TextStringObject(str 子类)——
    优先取 original_bytes，保证拿回原始字节而不是文本解码结果。"""
    ob = getattr(v, "original_bytes", None)
    if ob is not None:
        return bytes(ob)
    if isinstance(v, str):
        return v.encode("latin-1")
    return bytes(v)


def _load_params(pdf_path: str):
    from pypdf import PdfReader
    r = PdfReader(pdf_path)
    if not r.is_encrypted:
        return None
    enc = r.trailer["/Encrypt"].get_object()
    v = int(enc["/V"]); rev = int(enc["/R"])
    if v >= 4:
        raise ValueError(f"该 PDF 使用 AES/强化加密（V={v}, R={rev}），本工具不处理")
    length_bits = int(enc.get("/Length", 40))
    o = _as_bytes(enc["/O"]); u = _as_bytes(enc["/U"])
    p_unsigned = int(enc["/P"]) & 0xFFFFFFFF
    id_arr = r.trailer.get("/ID")
    id0 = _as_bytes(id_arr[0]) if id_arr else b""
    return {"v": v, "rev": rev, "n": length_bits // 8, "o": o, "u": u,
            "p": p_unsigned, "id0": id0, "length_bits": length_bits}


def _scan_chunk(task):
    lo, hi, params, length = task
    for i in range(lo, hi):
        cand = str(i).zfill(length).encode()
        if verify_user(cand, params):
            return cand.decode()
    return None


def cmd_probe(args):
    info = _load_params(args.file)
    if info is None:
        print("未加密，可直接读取。")
        return 0
    print(f"加密: 标准安全处理器 V={info['v']} R={info['rev']} 密钥 {info['length_bits']} 位")
    kind = "RC4（可设备端恢复）" if info["rev"] <= 3 else "AES（不可快速恢复）"
    print(f"算法: {kind}")
    return 0


def cmd_recover(args):
    info = _load_params(args.file)
    if info is None:
        print("未加密，无需恢复。")
        return 0
    if info["rev"] > 3:
        print("AES 加密（R>=4），本工具明确不支持 —— 请从下发渠道获取口令。")
        return 1

    params = (info["o"], info["u"], info["p"], info["id0"], info["n"], info["rev"])

    # 候选口令列表（免 consent）
    if args.pwds:
        for cand in [c.strip() for c in args.pwds.split(",") if c.strip()]:
            if verify_user(cand.encode("utf-8"), params):
                print(f"候选口令命中（长度 {len(cand)}）。")
                return _finish(args, cand)
        print("全部候选口令均不匹配。")
        return 2

    if not args.consent:
        print(COST_NOTICE)
        print("未提供 --consent，已停在恢复前（默认不做任何试探）。")
        return 2

    print(COST_NOTICE)
    length = args.length
    start = args.start or 0
    end = args.end if args.end is not None else 10 ** length
    print(f"开始恢复：digits × {length} 位，范围 [{start}, {end})")

    chunk = max(1, (end - start) // (mp.cpu_count() * 4) or 1)
    tasks = [(i, min(i + chunk, end), params, length) for i in range(start, end, chunk)]
    found = None
    done = 0
    with mp.Pool(processes=min(mp.cpu_count(), 16)) as pool:
        for res in pool.imap_unordered(_scan_chunk, tasks):
            done += chunk
            print(f"\r  已试 ~{min(done, end - start):,}/{end - start:,}", end="", flush=True)
            if res is not None:
                found = res
                break
    print()
    if found is None:
        print("未在范围内找到口令。")
        return 3
    print(f"恢复成功（口令长度 {len(found)}，未显示）。")
    return _finish(args, found)


def _finish(args, pwd: str) -> int:
    if args.show:
        print(f"口令: {pwd}")
    if not args.no_save:
        os.makedirs(WORK, exist_ok=True)
        new = not os.path.exists(PWD_SAVE)
        with open(PWD_SAVE, "a", encoding="utf-8") as f:
            if new:
                f.write("# 账单文件口令恢复记录 —— 明文保存，请妥善保管，别连同账单一起外发\n")
            f.write(f"{_dt.datetime.now():%Y-%m-%d %H:%M:%S}\t{os.path.basename(args.file)}\t{pwd}\n")
        print(f"口令已写入 {PWD_SAVE}（明文，注意保护）")
    if args.out_dir:
        out = _decrypt_copy(args.file, pwd, args.out_dir)
        if out:
            print(f"已生成无密码副本 -> {out}")
    return 0


def _decrypt_copy(pdf_path: str, pwd: str, out_dir: str):
    try:
        from pypdf import PdfReader, PdfWriter
        r = PdfReader(pdf_path)
        if r.decrypt(pwd) == 0:
            print("!! 口令校验通过但解密失败（异常情况）")
            return None
        w = PdfWriter()
        for pg in r.pages:
            w.add_page(pg)
        os.makedirs(out_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(pdf_path))[0]
        out = os.path.join(out_dir, base + ".解密副本.pdf")
        with open(out, "wb") as f:
            w.write(f)
        return out
    except Exception as e:
        print(f"!! 生成解密副本失败: {e}")
        return None


def main():
    ap = argparse.ArgumentParser(description="银行流水 PDF 设备端口令恢复（R2/R3 RC4）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("probe", help="只读探测加密方式")
    p1.add_argument("file")
    p1.set_defaults(func=cmd_probe)

    p2 = sub.add_parser("recover", help="候选口令 / 穷举恢复（+ 可选生成解密副本）")
    p2.add_argument("file")
    p2.add_argument("--pwds", default="", help="候选口令，逗号分隔（免 consent）")
    p2.add_argument("--consent", action="store_true", help="确认在设备端穷举（先打印代价说明）")
    p2.add_argument("--length", type=int, default=6, help="口令长度（默认 6；仅支持纯数字）")
    p2.add_argument("--start", type=int, default=None)
    p2.add_argument("--end", type=int, default=None)
    p2.add_argument("--out-dir", default=None, help="输出无密码副本的目录（可选）")
    p2.add_argument("--show", action="store_true", help="在终端显示口令（仅限本地终端）")
    p2.add_argument("--no-save", action="store_true", help="不把口令写入本地文件")
    p2.set_defaults(func=cmd_recover)

    args = ap.parse_args()
    if not os.path.isfile(args.file):
        print(f"!! 文件不存在: {args.file}")
        return 1
    try:
        return args.func(args)
    except ValueError as e:
        print(f"!! {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
