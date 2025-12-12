#!/usr/bin/env python3

import os.path
import sys

ror = lambda cbyte: ((cbyte * 0x201) >> 1) & 0x1FF
rol = lambda cbyte: ((cbyte * 0x201) >> 8) & 0x1FF


def checkbin(*, infn, buf, beg, end=None):
    if end is None:
        end = beg + len(buf) - 1
    assert beg <= end  # cannot dump an empty region or a negative-sized one
    assert (
        len(buf) == end + 1 - beg
    )  # supplied buffer size must match that computed from beginning and end addresses
    output = [f"{os.path.basename(infn)!r} BEG: *{beg:X}.{end:X} END:", ""]
    cksum = beg
    addr = beg
    carry = 0x100
    while addr <= (end | 7):
        if addr <= end:
            if (addr % 8 == 0) or (addr == beg):
                if len(output) % 11 == 1:
                    output += [""]
                output += [f"{addr:04X}-"]
            output[-1] += f" {buf[0]:02X}"
            carry = 0x100  # carry = 0x000 if (addr & 7) == 7 else 0x100
            tmp = rol(ror(carry | buf[0]) ^ (cksum & 0xFF)) ^ (cksum >> 8)
            cksum = (cksum & 0xFF00) | ((tmp) & 0xFF)
            carry = tmp & 0x100
            cksum = (cksum & 0xFF) | (
                (ror((carry | (cksum & 0xFF)) ^ (cksum >> 8)) & 0xFF) << 8
            )
        else:
            output[-1] += "   "
        if addr % 8 == 7:
            if addr == (beg | 7):
                output[-1] += "   " * (beg & 7)
            output[-1] += f"  ${((cksum * 0x10001) & 0xffff00) >> 8:04X}"
        addr += 1
        buf = buf[1:]
    return "\n".join(output)


def smoketest():
    assert checkbin(
        infn="one-byte smoke test 1", buf=b"\x00", beg=0x391, end=0x391
    ) == (
        """
'one-byte smoke test 1' BEG: *391.391 END:

0391- 00                       $2111
        """.strip()
    )
    assert checkbin(infn="one-byte smoke test 2", buf=b"\x4c", beg=0x0, end=0x0) == (
        """
'one-byte smoke test 2' BEG: *0.0 END:

0000- 4C                       $4CA6
        """.strip()
    )
    assert checkbin(
        infn="one-byte smoke test 3", buf=b"\x20", beg=0x300, end=0x300
    ) == (
        """
'one-byte smoke test 3' BEG: *300.300 END:

0300- 20                       $2390
        """.strip()
    )
    assert checkbin(
        infn="checkbin_300_3CD_raw.bin",
        buf=(
            b"\x20\x58\xff\xba\xca\xbd\x00\x01"
            b"\x18\x69\x1f\x8d\xf9\x03\x85\x62"
            b"\xe8\xbd\x00\x01\x69\x00\x8d\xfa"
            b"\x03\x85\x63\xa9\x4c\x8d\xf8\x03"
            b"\x60\x20\x8e\xfd\xa9\x0a\x85\x0a"
            b"\xa0\x00\x84\x31\x20\xa7\xff\xa9"
            b"\xff\x85\x31\xa5\x3c\x85\x0b\xa5"
            b"\x3d\x85\x0c\x20\xa7\xff\xa0\x55"
            b"\xa9\x10\x91\x62\xa9\xfb\xc8\x91"
            b"\x62\xa0\x00\xf0\x45\xa5\x3c\x29"
            b"\x07\xd0\x42\x38\xa9\x1f\xe5\x24"
            b"\xaa\x20\x4a\xf9\xa9\xa4\x20\xed"
            b"\xfd\xa5\x0b\xa6\x0c\x20\x41\xf9"
            b"\xc6\x0a\xd0\x26\x20\x8e\xfd\xa9"
            b"\x0a\x85\x0a\xad\x00\xc0\xea\xea"
            b"\x8d\x10\xc0\xc9\x83\xf0\x48\xc9"
            b"\xa0\xf0\xbb\xc9\x9b\xd0\x0b\xa9"
            b"\xea\xa0\x55\x91\x62\xc8\x91\x62"
            b"\xa0\x00\x20\x92\xfd\xa9\xa0\x20"
            b"\xed\xfd\xb1\x3c\x48\x20\xda\xfd"
            b"\x68\x6a\x45\x0b\x2a\x45\x0c\x85"
            b"\x0b\x45\x0c\x6a\x85\x0c\x20\xba"
            b"\xfc\x90\x9a\xa9\x1f\xe5\x24\xaa"
            b"\x20\x4a\xf9\xa9\xa4\x20\xed\xfd"
            b"\xa5\x0b\xa6\x0c\x20\x41\xf9\x20"
            b"\x8e\xfd\x8d\x10\xc0\x60"
        ),
        beg=0x300,
    ) == (
        """
'checkbin_300_3CD_raw.bin' BEG: *300.3CD END:

0300- 20 58 FF BA CA BD 00 01  $B2E1
0308- 18 69 1F 8D F9 03 85 62  $286C
0310- E8 BD 00 01 69 00 8D FA  $D2ED
0318- 03 85 63 A9 4C 8D F8 03  $68E2
0320- 60 20 8E FD A9 0A 85 0A  $2066
0328- A0 00 84 31 20 A7 FF A9  $5284
0330- FF 85 31 A5 3C 85 0B A5  $0223
0338- 3D 85 0C 20 A7 FF A0 55  $D448
0340- A9 10 91 62 A9 FB C8 91  $6CDF
0348- 62 A0 00 F0 45 A5 3C 29  $E502

0350- 07 D0 42 38 A9 1F E5 24  $E2B6
0358- AA 20 4A F9 A9 A4 20 ED  $3E81
0360- FD A5 0B A6 0C 20 41 F9  $459D
0368- C6 0A D0 26 20 8E FD A9  $2DD5
0370- 0A 85 0A AD 00 C0 EA EA  $5EB6
0378- 8D 10 C0 C9 83 F0 48 C9  $C54A
0380- A0 F0 BB C9 9B D0 0B A9  $6C5B
0388- EA A0 55 91 62 C8 91 62  $29C6
0390- A0 00 20 92 FD A9 A0 20  $F038
0398- ED FD B1 3C 48 20 DA FD  $E122

03A0- 68 6A 45 0B 2A 45 0C 85  $C531
03A8- 0B 45 0C 6A 85 0C 20 BA  $059B
03B0- FC 90 9A A9 1F E5 24 AA  $C561
03B8- 20 4A F9 A9 A4 20 ED FD  $8DF6
03C0- A5 0B A6 0C 20 41 F9 20  $2A83
03C8- 8E FD 8D 10 C0 60        $C4C6
        """.strip()
    )


smoketest()

if __name__ == "__main__":
    try:
        _, infn, beg = sys.argv
        end = None
    except:
        _, infn, beg, end = (
            sys.argv
        )  # usage: python checkbin.py INFILENAME BEGADDRHEX ENDADDRHEX
        end = int(end, 16)  # usage: python checkbin.py INFILENAME BEGADDRHEX ENDADDRHEX
    beg = int(beg, 16)  # usage: python checkbin.py INFILENAME BEGADDRHEX ENDADDRHEX
    buf = open(infn, "rb").read()
    print(checkbin(infn=infn, buf=buf, beg=beg, end=end))
