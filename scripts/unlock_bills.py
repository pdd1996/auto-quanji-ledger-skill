# -*- coding: utf-8 -*-
"""
设备端口令恢复（unlock）—— 当账单压缩包口令拿不到/丢了的最后手段。

背景：
  微信/支付宝账单 zip 用 ZipCrypto 传统加密。密钥流只取决于口令，
  口令空间若为短数字（平台常见 6 位），在本机可以在秒级完成恢复。
  恢复全程在用户设备上进行，口令不打印、不上传（除非用户显式 --show）。

硬边界（与 references/privacy.md 一致）：
  * 默认不做任何试探；必须用户显式给出 --consent 才进入恢复模式，
    并在开始前打印代价说明（平台协议风险 / 商店审核风险）。
  * 恢复出的口令默认只写本地文件（明文，有警告），不打印到终端；
    --show 仅供用户在本地终端自行查看。
  * 只处理 ZipCrypto 传统加密；AES（compress_type=99）会明确拒绝。

用法：
    # 探测（只读）
    python scripts/unlock_bills.py probe "账单.zip"

    # 候选口令（不需要 --consent，等价于 qqmail_bills decrypt）
    python scripts/unlock_bills.py recover "账单.zip" --pwds "111111,222222"

    # 设备端恢复：6 位数字（需要 --consent；先打印代价说明）
    python scripts/unlock_bills.py recover "账单.zip" --consent

    # 恢复后解密到工作目录（默认 ~/.bill-lens/mail_bills）
    python scripts/unlock_bills.py recover "账单.zip" --consent --out-dir <目录>
"""
from __future__ import annotations

import argparse
import datetime as _dt
import multiprocessing as mp
import os
import struct
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

WORK = os.environ.get("BILL_WORK") or os.path.join(os.path.expanduser("~"), ".bill-lens")
MAILDIR = os.environ.get("QQMAIL_DIR") or os.path.join(WORK, "mail_bills")
PWD_SAVE = os.path.join(WORK, "recovered_pwds.local.txt")

COST_NOTICE = """\
────────────────────────────────────────────────────────────
代价说明（继续即视为你明确要求在本设备上进行口令恢复）
  * 法律：处置你本人的文件，不构成"未经授权访问系统"；
  * 平台：可能被平台视为"规避技术保护措施"，存在违反用户协议的风险；
  * 上架：内置恢复逻辑是应用商店审核风险点，对外分发前请评估；
  * 收益：通常只是省掉一次从公众号/申请页复制口令。
  约束：全程仅在本机进行；口令不打印、不进对话、不上传。
────────────────────────────────────────────────────────────"""

# ── ZipCrypto 核心（纯标准库实现的密钥流）──────────────────────────
def _make_crc_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c & 0xFFFFFFFF)
    return table


CRC_TABLE = _make_crc_table()


class _Keys:
    __slots__ = ("k0", "k1", "k2")

    def __init__(self, pwd: bytes):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in pwd:
            self.update(b)

    def update(self, c: int):
        self.k0 = (self.k0 >> 8) ^ CRC_TABLE[(self.k0 ^ c) & 0xFF]
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = (self.k2 >> 8) ^ CRC_TABLE[(self.k2 ^ (self.k1 >> 24)) & 0xFF]

    def decrypt(self, c: int) -> int:
        t = (self.k2 | 2) & 0xFFFFFFFF
        return (c ^ ((t * (t ^ 1)) >> 8)) & 0xFF


def _read_local_parts(zf: zipfile.ZipFile, info: zipfile.ZipInfo):
    """解析本地文件头，返回 (加密头12字节, 加密数据 bytes, 本地时间字段)。"""
    with open(zf.filename, "rb") as f:
        f.seek(info.header_offset)
        raw = f.read(30)
        if raw[:4] != b"PK\x03\x04":
            raise ValueError(f"{info.filename}: 本地文件头损坏（central 目录偏移可能错位）")
        fn_len, ex_len = struct.unpack("<HH", raw[26:30])
        local_mtime = struct.unpack("<H", raw[10:12])[0]
        f.seek(info.header_offset + 30 + fn_len + ex_len)
        header = f.read(12)
        data = f.read(max(0, info.compress_size - 12))
    return header, data, local_mtime


def _entry_crypto_info(zf: zipfile.ZipFile, info: zipfile.ZipInfo):
    """返回 (加密头12字节, 校验字节候选集) 或 None。"""
    if not (info.flag_bits & 0x1):
        return None
    if info.compress_type == 99 or (info.flag_bits & 0x40):
        raise ValueError(f"{info.filename}: 非 ZipCrypto（AES/强加密），本工具拒绝处理")

    header, _data, local_mtime = _read_local_parts(zf, info)

    # 校验字节：bit3（数据描述符）置位时用 DOS 时间高字节，否则用 CRC 高字节
    y, mo, d, h, mi, s = info.date_time
    dos_time_central = (h << 11) | (mi << 5) | (s // 2)
    checks = set()
    if info.flag_bits & 0x8:
        checks.add((local_mtime >> 8) & 0xFF)
        checks.add((dos_time_central >> 8) & 0xFF)
    else:
        checks.add((info.CRC >> 24) & 0xFF)
    return header, checks


def _verify_hits_loop(zf: zipfile.ZipFile, info: zipfile.ZipInfo, hits: list):
    for cand in hits:
        if _verify_password(zf, info, cand.encode("utf-8")):
            return cand
    return None


def _verify_hits_fast(zf: zipfile.ZipFile, info: zipfile.ZipInfo, hits: list, length: int):
    """批量完整校验头校验幸存者——等价于逐条 zipfile 校验，但快一两个数量级。

    背景：CPython zipfile 的解密器是纯 Python 的，且头校验用的就是同一个检查字节，
    所以每条幸存者都要整条流跑一遍 Python 级解密（账单约 10KB/条，实测 ~16ms/条；
    几千条幸存者 = 几十秒，比扫描本身还慢）。这里把"解密 + 解压 + CRC"整段
    搬到 numpy + zlib 批量做：实测 3884 条幸存者 ~1s。
    口径不变：zlib 的 CRC32 与中央目录 CRC 比对；命中后再回 zipfile 复核一次。
    numpy 不可用、压缩方式未知或条目过大时，退回逐条 zipfile 校验。
    """
    if not hits:
        return None
    try:
        import numpy as np
        import zlib
    except ImportError:
        return _verify_hits_loop(zf, info, hits)
    header, data, _lm = _read_local_parts(zf, info)
    if info.compress_type not in (0, 8) or any(len(c) != length for c in hits):
        return _verify_hits_loop(zf, info, hits)
    L = len(data)
    if L <= 0 or L > 200_000_000:
        return _verify_hits_loop(zf, info, hits)
    # 分批做批量校验：内存受控（每批 ≤2048 条），并把工作集留在缓存里
    for g in range(0, len(hits), 2048):
        sub = hits[g:g + 2048]
        found = _verify_batch_np(np, zf, info, sub, length, header, data)
        if found is not None:
            return found
    return None


def _verify_batch_np(np, zf, info, hits: list, length: int, header: bytes, data: bytes):
    """单批（≤2048 条）幸存者：numpy 批量解密整条流 + zlib inflate/CRC。"""
    import zlib

    N = len(hits)
    L = len(data)
    U32 = np.uint32
    T = np.array(CRC_TABLE, dtype=np.uint32)
    C_MUL = U32(134775813)
    ONE = U32(1)
    B255 = U32(0xFF)
    b1 = np.empty(N, dtype=np.uint32)
    b2 = np.empty(N, dtype=np.uint32)
    bt = np.empty(N, dtype=np.uint32)
    bc = np.empty(N, dtype=np.uint32)

    def upd(k0, k1, k2, c):
        np.bitwise_and(k0, B255, out=b1)
        np.bitwise_xor(b1, c, out=b1)
        np.take(T, b1, out=b2)
        np.right_shift(k0, U32(8), out=k0)
        np.bitwise_xor(k0, b2, out=k0)
        np.bitwise_and(k0, B255, out=b1)
        np.add(k1, b1, out=k1)
        np.multiply(k1, C_MUL, out=k1)
        np.add(k1, ONE, out=k1)
        np.bitwise_and(k2, B255, out=b1)
        np.right_shift(k1, U32(24), out=b2)
        np.bitwise_xor(b1, b2, out=b1)
        np.take(T, b1, out=b2)
        np.right_shift(k2, U32(8), out=k2)
        np.bitwise_xor(k2, b2, out=k2)
        return k0, k1, k2

    k0 = np.full(N, 0x12345678, dtype=np.uint32)
    k1 = np.full(N, 0x23456789, dtype=np.uint32)
    k2 = np.full(N, 0x34567890, dtype=np.uint32)
    pw = np.array([[ord(ch) for ch in cand] for cand in hits], dtype=np.uint32)  # (N, length)
    for j in range(length):
        k0, k1, k2 = upd(k0, k1, k2, pw[:, j])
    cts = np.frombuffer(header + data, dtype=np.uint8)
    for i in range(12):                       # 12 字节加密头（第 12 字节明文在此不再使用）
        np.bitwise_or(k2, U32(2), out=bt)
        np.bitwise_xor(bt, ONE, out=b1)
        np.multiply(bt, b1, out=bt)
        np.right_shift(bt, U32(8), out=bc)
        np.bitwise_xor(bc, U32(int(cts[i])), out=bc)
        np.bitwise_and(bc, B255, out=bc)
        k0, k1, k2 = upd(k0, k1, k2, bc)
    out = np.empty((L, N), dtype=np.uint8)
    for j in range(L):                        # 整条数据流：解密结果按列存放
        np.bitwise_or(k2, U32(2), out=bt)
        np.bitwise_xor(bt, ONE, out=b1)
        np.multiply(bt, b1, out=bt)
        np.right_shift(bt, U32(8), out=bc)
        np.bitwise_xor(bc, U32(int(cts[12 + j])), out=bc)
        np.bitwise_and(bc, B255, out=bc)
        k0, k1, k2 = upd(k0, k1, k2, bc)
        np.copyto(out[j], bc, casting="unsafe")

    crc_expect = info.CRC & 0xFFFFFFFF
    for i in range(N):
        comp = out[:, i].tobytes()
        if info.compress_type == 8:
            try:
                # 快速剔除：错口令的"压缩流"几乎都在前 1KB 内被 inflate 判死
                zlib.decompressobj(-15).decompress(comp[:1024])
            except Exception:
                continue
        try:
            if info.compress_type == 8:
                d = zlib.decompressobj(-15)
                plain = d.decompress(comp) + d.flush()
            else:
                plain = comp
        except Exception:
            continue
        if (zlib.crc32(plain) & 0xFFFFFFFF) == crc_expect:
            cand = hits[i]
            if _verify_password(zf, info, cand.encode("utf-8")):
                return cand
    return None


def _verify_password(zf: zipfile.ZipFile, info: zipfile.ZipInfo, pwd: bytes) -> bool:
    try:
        with zf.open(info, "r", pwd=pwd) as fp:
            while fp.read(1 << 16):
                pass
        return True
    except Exception:
        return False


def _scan_zip_chunk(task):
    """多进程工作块：在 [lo, hi) 内做头校验筛选，幸存者就地用 zipfile 完整校验。"""
    import io as _io
    import contextlib as _ctx
    lo, hi, header, checks, length, zip_path, entry_idx = task
    with _ctx.redirect_stdout(_io.StringIO()):
        hits = _recover_numpy(header, checks, length, lo, hi)
    if not hits:
        return None
    zf = zipfile.ZipFile(zip_path)
    info = [i for i in zf.infolist() if not i.is_dir() and (i.flag_bits & 0x1)][entry_idx]
    return _verify_hits_fast(zf, info, hits, length)


def _recover_numpy(header: bytes, checks: set, length: int, start: int, end: int):
    """numpy 向量化穷举（uint32 融合管线 + 全 in-place 缓冲）。

    返回"头校验"命中的候选口令列表（仍需 zipfile 完整校验兜底）。
    实测（8 核机器，100 万候选）：本实现 ≈0.7s，初版 uint64 实现 ≈2.0s。
    """
    import numpy as np

    U32 = np.uint32
    T = np.array(CRC_TABLE, dtype=np.uint32)
    C_MUL = U32(134775813)
    ONE = U32(1)
    B255 = U32(0xFF)
    ct = [int(b) for b in header]           # 12 个密文字节（对全体候选相同）
    chk = [U32(c) for c in sorted(checks)]

    hits = []
    step = 262144                           # 分块：工作集留缓存，实测最优
    bufs = None
    n_cap = 0
    for lo in range(start, end, step):
        hi = min(lo + step, end)
        n = hi - lo
        if n > n_cap:                       # 四个缓冲只增不减，跨块复用
            bufs = tuple(np.empty(n, dtype=np.uint32) for _ in range(4))
            n_cap = n
        b1, b2, bt, bc = (b[:n] for b in bufs)

        k0 = np.full(n, 0x12345678, dtype=np.uint32)
        k1 = np.full(n, 0x23456789, dtype=np.uint32)
        k2 = np.full(n, 0x34567890, dtype=np.uint32)

        # 候选数字 → ASCII 字节列，按 MSB 先喂入
        tmp = np.arange(lo, hi, dtype=np.uint32)
        digits = []
        for _ in range(length):
            digits.append((tmp % U32(10)) + U32(48))
            tmp = tmp // U32(10)
        digits.reverse()

        def upd(k0, k1, k2, c):
            # 口径（与 CPython zipfile 一致）：
            #   k0 用「旧 k0」低字节做索引；k1 用「更新后 k0」低字节；
            #   全 uint32 回绕运算，掩码全部折进索引计算。
            # 注：c 不得与 b1/b2 混叠（头字节轮用独立的 bc 缓冲）。
            np.bitwise_and(k0, B255, out=b1)
            np.bitwise_xor(b1, c, out=b1)
            np.take(T, b1, out=b2)
            np.right_shift(k0, U32(8), out=k0)
            np.bitwise_xor(k0, b2, out=k0)
            np.bitwise_and(k0, B255, out=b1)
            np.add(k1, b1, out=k1)
            np.multiply(k1, C_MUL, out=k1)
            np.add(k1, ONE, out=k1)
            np.bitwise_and(k2, B255, out=b1)
            np.right_shift(k1, U32(24), out=b2)
            np.bitwise_xor(b1, b2, out=b1)
            np.take(T, b1, out=b2)
            np.right_shift(k2, U32(8), out=k2)
            np.bitwise_xor(k2, b2, out=k2)
            return k0, k1, k2

        for c in digits:
            k0, k1, k2 = upd(k0, k1, k2, c)
        # 头 12 字节：ZipCrypto 的密钥更新用「明文」字节 c = 密文 ^ f(k2)
        for i in range(11):
            np.bitwise_or(k2, U32(2), out=bt)
            np.bitwise_xor(bt, ONE, out=b1)
            np.multiply(bt, b1, out=bt)     # uint32 回绕不影响 bits8..15
            np.right_shift(bt, U32(8), out=bc)
            np.bitwise_xor(bc, U32(ct[i]), out=bc)
            np.bitwise_and(bc, B255, out=bc)
            k0, k1, k2 = upd(k0, k1, k2, bc)
        np.bitwise_or(k2, U32(2), out=bt)
        np.bitwise_xor(bt, ONE, out=b1)
        np.multiply(bt, b1, out=bt)
        np.right_shift(bt, U32(8), out=bc)
        np.bitwise_xor(bc, U32(ct[11]), out=bc)
        np.bitwise_and(bc, B255, out=bc)
        sel = bc == chk[0]
        for c in chk[1:]:
            sel |= bc == c
        for pos in np.nonzero(sel)[0]:
            # 前导零必须补：口令 "042424" 与 "42424" 的字节序列不同，密钥流也不同
            hits.append(str(lo + int(pos)).zfill(length))
        print(f"\r  已试 {hi - start:,}/{end - start:,}", end="", flush=True)
    print()
    return hits


def _recover_pure_python(header: bytes, checks: set, length: int, start: int, end: int):
    hits = []
    for i in range(start, end):
        pwd = str(i).zfill(length).encode()
        k = _Keys(pwd)
        for bx in header[:11]:
            p = k.decrypt(bx)
            k.update(p)          # 密钥更新用明文（与 zlib/zipfile 口径一致）
        if k.decrypt(header[11]) in checks:
            # 头校验过了，交给 zipfile 做完整校验
            hits.append(pwd.decode())
        if i % 200000 == 0:
            print(f"\r  已试 {i - start:,}/{end - start:,}", end="", flush=True)
    print()
    return hits


def _save_pwd(path: str, src: str, pwd: str):
    new = not os.path.exists(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write("# 账单压缩包口令恢复记录 —— 明文保存，请妥善保管，别连同账单一起外发\n")
        f.write(f"{_dt.datetime.now():%Y-%m-%d %H:%M:%S}\t{os.path.basename(src)}\t{pwd}\n")


def _decrypt_to(zf: zipfile.ZipFile, pwd: bytes, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    out_paths = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        target = os.path.join(out_dir, info.filename)
        with zf.open(info, "r", pwd=pwd) as fp, open(target, "wb") as out:
            while True:
                chunk = fp.read(1 << 16)
                if not chunk:
                    break
                out.write(chunk)
        out_paths.append(target)
    return out_paths


def cmd_probe(args):
    with zipfile.ZipFile(args.file) as zf:
        for info in zf.infolist():
            enc = bool(info.flag_bits & 0x1)
            print(f"条目: {info.filename}")
            print(f"  加密: {'是' if enc else '否'} | 压缩: {info.compress_type} | flag: 0x{info.flag_bits:04X}")
            if enc and info.compress_type == 99:
                print("  => AES/强加密：不可恢复（无已知弱点），只能用户提供口令")
            elif enc:
                print("  => ZipCrypto：可在设备端恢复（需 --consent）")
            else:
                print("  => 未加密：直接解析")


def cmd_recover(args):
    zf = zipfile.ZipFile(args.file)
    infos = [i for i in zf.infolist() if not i.is_dir() and (i.flag_bits & 0x1)]
    if not infos:
        print("文件未加密，无需恢复。")
        return 0
    info = infos[0]

    # 1) 候选口令列表（免 consent）
    if args.pwds:
        for cand in [p.strip() for p in args.pwds.split(",") if p.strip()]:
            if _verify_password(zf, info, cand.encode("utf-8")):
                print(f"候选口令命中（长度 {len(cand)}）。")
                if args.show:
                    print(f"口令: {cand}")
                if not args.no_save:
                    _save_pwd(PWD_SAVE, args.file, cand)
                    print(f"口令已写入 {PWD_SAVE}（明文，注意保护）")
                return _finish(zf, cand.encode("utf-8"), args)
        print("全部候选口令均不匹配。")
        return 2

    # 2) 穷举恢复（必须 consent）
    if not args.consent:
        print(COST_NOTICE)
        print("未提供 --consent，已停在恢复前（默认不做任何试探）。")
        print("如要继续：加 --consent；或先用 --pwds 提供候选口令。")
        return 2

    print(COST_NOTICE)
    header, checks = _entry_crypto_info(zf, info)
    start = args.start if args.start is not None else 0
    end = args.end if args.end is not None else 10 ** args.length
    space = 10 ** args.length          # 纯数字口令的合法空间上限
    if end > space:
        print(f"提示：{args.length} 位数字空间上限为 {space:,}，已将 end 截到上限。")
        end = space
    if start >= end:
        print("!! 范围为空。")
        return 2
    total = end - start
    print(f"开始恢复：{args.charset} × {args.length} 位，范围 [{start}, {end})")

    # 大范围自动多进程（小范围单进程更快：省去进程启动开销）
    workers = args.workers if args.workers else (min(mp.cpu_count(), 8) if total >= 3_000_000 else 1)
    found = None
    if workers > 1:
        chunk = max(1, total // (workers * 4))
        tasks = [(lo, min(lo + chunk, end), header, checks, args.length, args.file, 0)
                 for lo in range(start, end, chunk)]
        print(f"  并行恢复：{workers} 进程 / {len(tasks)} 块")
        done = 0
        with mp.Pool(workers) as pool:
            for res in pool.imap_unordered(_scan_zip_chunk, tasks):
                done += 1
                print(f"\r  已完成 {done}/{len(tasks)} 块", end="", flush=True)
                if res is not None:
                    found = res
                    pool.terminate()
                    break
        print()
        if found is None:
            print("未在范围内找到口令。")
            return 3
    else:
        try:
            import numpy  # noqa: F401
            hits = _recover_numpy(header, checks, args.length, start, end)
        except ImportError:
            print("（未安装 numpy，退回纯 Python 实现，速度较慢）")
            hits = _recover_pure_python(header, checks, args.length, start, end)

        found = _verify_hits_fast(zf, info, hits, args.length)
        if found is None:
            print(f"未在范围内找到口令（头校验候选 {len(hits)} 个，均未通过完整校验）。")
            return 3

    print(f"恢复成功（口令长度 {len(found)}，未显示）。")
    if args.show:
        print(f"口令: {found}")
    if not args.no_save:
        _save_pwd(PWD_SAVE, args.file, found)
        print(f"口令已写入 {PWD_SAVE}（明文，注意保护）")
    return _finish(zf, found.encode(), args)


def _finish(zf, pwd: bytes, args) -> int:
    out_dir = args.out_dir or MAILDIR
    paths = _decrypt_to(zf, pwd, out_dir)
    for p in paths:
        print(f"已解密 -> {p}")
    print("提示：把解密后的文件放进工作目录即可被 qqmail_bills.py 解析入库。")
    return 0


def main():
    ap = argparse.ArgumentParser(description="账单 zip 设备端口令恢复（ZipCrypto）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("probe", help="只读探测加密方式")
    p1.add_argument("file")
    p1.set_defaults(func=cmd_probe)

    p2 = sub.add_parser("recover", help="候选口令 / 穷举恢复 + 解密")
    p2.add_argument("file")
    p2.add_argument("--pwds", default="", help="候选口令，逗号分隔（免 consent）")
    p2.add_argument("--consent", action="store_true", help="确认在本设备进行穷举恢复（会先打印代价说明）")
    p2.add_argument("--charset", default="digits", choices=["digits"], help="候选字符集（目前支持 digits）")
    p2.add_argument("--length", type=int, default=6, help="口令长度（默认 6）")
    p2.add_argument("--start", type=int, default=None, help="范围起点（含）")
    p2.add_argument("--end", type=int, default=None, help="范围终点（不含）")
    p2.add_argument("--out-dir", default=None, help="解密输出目录（默认 ~/.bill-lens/mail_bills）")
    p2.add_argument("--show", action="store_true", help="在终端显示口令（仅限本地终端使用）")
    p2.add_argument("--no-save", action="store_true", help="不把口令写入本地文件")
    p2.add_argument("--workers", type=int, default=None,
                    help="并行进程数（默认：范围 ≥3,000,000 时自动取 CPU 核数，否则 1）")
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
