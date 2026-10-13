# -*- coding: utf-8 -*-
"""
口令恢复离线自检 —— 全程不接触任何真实账单。

构造已知口令的合成样本（zip：STORE/bit3/DEFLATE 三种形态；PDF：RC4-128），
然后跑恢复管线，并让 **CPython zipfile / pypdf 作为独立裁判**交叉验证：
  * 合成包必须能被 CPython 用口令打开（证明样本本身合规）；
  * 恢复器必须能在小范围内找回口令并解出与原文一致的字节。

用法：
    python scripts/selftest_unlock.py
"""
from __future__ import annotations

import contextlib
import io
import os
import random
import struct
import sys
import tempfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import unlock_bills  # noqa: E402
from unlock_bills import _Keys  # noqa: E402

TEST_PWD = "042424"
TEST_PWD_IDX = int(TEST_PWD)


# ── 合成 zip 构造（ZipCrypto 加密写出去；Python zipfile 只能读不能写加密包）──
def _enc_stream(pwd: bytes, plain: bytes) -> bytes:
    k = _Keys(pwd)
    out = bytearray()
    for p in plain:
        t = (k.k2 | 2) & 0xFFFFFFFF
        out.append((p ^ ((t * (t ^ 1)) >> 8)) & 0xFF)
        k.update(p)
    return bytes(out)


def build_test_zip(path: str, entries, pwd: bytes, deflate: bool, bit3: bool):
    rnd = random.Random(42)
    local_parts, central_parts, offset = [], [], 0
    for name, data in entries:
        name_b = name.encode("utf-8")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        if deflate:
            co = zlib.compressobj(6, zlib.DEFLATED, -15)   # 裸 DEFLATE
            comp = co.compress(data) + co.flush()
            method = 8
        else:
            comp = data
            method = 0
        dostime = (20 << 11) | (8 << 5) | (28 // 2)
        dosdate = ((2026 - 1980) << 9) | (10 << 5) | 12

        check = (dostime >> 8) & 0xFF if bit3 else (crc >> 24) & 0xFF
        header = bytes(rnd.randrange(256) for _ in range(11)) + bytes([check])
        enc = _enc_stream(pwd, header + comp)

        flags = 0x0801 | (0x0008 if bit3 else 0)   # 0x0800 = UTF-8 文件名（真实账单包同款）
        if bit3:
            lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method,
                             dostime, dosdate, 0, 0, 0, len(name_b), 0)
            tail = struct.pack("<IIII", 0x08074B50, crc, len(enc), len(data))
        else:
            lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method,
                             dostime, dosdate, crc, len(enc), len(data), len(name_b), 0)
            tail = b""
        local_parts.append(lh + name_b + enc + tail)

        ch = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method,
                         dostime, dosdate, crc, len(enc), len(data),
                         len(name_b), 0, 0, 0, 0, 0, offset)
        central_parts.append(ch + name_b)
        offset += len(lh) + len(name_b) + len(enc) + len(tail)

    cd = b"".join(central_parts)
    body = b"".join(local_parts)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                       len(cd), len(body), 0)
    with open(path, "wb") as f:
        f.write(body + cd + eocd)


def check_zip_case(tmp: str, name: str, deflate: bool, bit3: bool) -> bool:
    payload = ("账单自检样本\n" + "".join(
        f"2026-07-{i % 28 + 1:02d} 10:00:00,商户{i},支出,{i}.00,交易成功\n" for i in range(60)
    )).encode("utf-8")
    p = os.path.join(tmp, name)
    build_test_zip(p, [("自检.csv", payload)], TEST_PWD.encode(), deflate, bit3)

    # 裁判 1：CPython zipfile 必须能用口令读通（样本合规）
    with zipfile.ZipFile(p) as zf:
        info = zf.infolist()[0]
        assert zf.read(info, pwd=TEST_PWD.encode()) == payload, name

        # 恢复器：小范围扫描（覆盖 042424，含前导零路径）
        header, checks = unlock_bills._entry_crypto_info(zf, info)
        lo, hi = TEST_PWD_IDX - 500, TEST_PWD_IDX + 500
        quiet = contextlib.redirect_stdout(io.StringIO())
        try:
            import numpy  # noqa: F401
            with quiet:
                hits = unlock_bills._recover_numpy(header, checks, 6, lo, hi)
        except ImportError:
            with quiet:
                hits = unlock_bills._recover_pure_python(header, checks, 6, lo, hi)
        found = next((h for h in hits if unlock_bills._verify_password(zf, info, h.encode())), None)
        assert found == TEST_PWD, f"{name}: 恢复结果 {found!r} != {TEST_PWD!r}"

        # 裁判 2：解密产物与原文逐字节一致
        out = os.path.join(tmp, name + ".out")
        os.makedirs(out, exist_ok=True)
        unlock_bills._decrypt_to(zf, found.encode(), out)
        produced = os.listdir(out)
        assert len(produced) == 1, name + f": 产物数量异常 {produced}"
        with open(os.path.join(out, produced[0]), "rb") as f:
            assert f.read() == payload, name + ": 解密内容不一致"
    return True


# ── 合成 PDF（R3 / RC4-128）──────────────────────────────────────
def check_pdf_case(tmp: str) -> bool:
    try:
        import unlock_pdf
    except Exception as e:  # noqa: BLE001
        print(f"  [跳过] unlock_pdf 依赖不可用: {e}")
        return True
    from pypdf import PdfWriter
    p = os.path.join(tmp, "自检.pdf")
    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    w.encrypt(user_password=TEST_PWD, owner_password="self-test-owner", algorithm="RC4-128")
    with open(p, "wb") as f:
        w.write(f)

    info = unlock_pdf._load_params(p)
    assert info and info["rev"] == 3, "样本不是 R3"
    params = (info["o"], info["u"], info["p"], info["id0"], info["n"], info["rev"])
    assert unlock_pdf.verify_user(TEST_PWD.encode(), params), "正确口令未通过校验"
    assert not unlock_pdf.verify_user(b"999999", params), "错误口令通过了校验"
    got = unlock_pdf._scan_chunk((TEST_PWD_IDX - 10, TEST_PWD_IDX + 10, params, 6))
    assert got == TEST_PWD, f"恢复结果 {got!r} != {TEST_PWD!r}"
    return True


def main() -> int:
    print("口令恢复自检（离线；不接触任何真实账单）")
    ok = 0
    cases = [
        ("syn_store_clear.zip", False, False),
        ("syn_store_bit3.zip", False, True),
        ("syn_deflate_bit3.zip", True, True),
    ]
    with tempfile.TemporaryDirectory(prefix="unlock_selftest_") as tmp:
        for name, deflate, bit3 in cases:
            try:
                check_zip_case(tmp, name, deflate, bit3)
                print(f"  [通过] {name}")
                ok += 1
            except Exception as e:  # noqa: BLE001
                print(f"  [失败] {name}: {type(e).__name__}: {e}")
        try:
            if check_pdf_case(tmp):
                print("  [通过] 自检.pdf (R3 RC4-128)")
                ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"  [失败] 自检.pdf: {type(e).__name__}: {e}")
    total = len(cases) + 1
    print(f"结果: {ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
