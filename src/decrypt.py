import argparse
import base64
import binascii
import collections
import struct
import uuid
import xml.etree.ElementTree as ET
from collections import deque

from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from pymp4.parser import Box
from pymp4.util import BoxUtil

if not hasattr(collections, "Sequence"):
    collections.Sequence = collections.abc.Sequence

class KeyMap:
    def __init__(self):
        self.keys = {}

    def add(self, kid, key):
        print(f"[DEBUG] Adding key for KID {kid}")
        self.keys[kid.lower()] = key

    def get(self, kid):
        key = self.keys.get(kid.lower())
        print(f"[DEBUG] Retrieving key for KID {kid}: {'Found' if key else 'Not found'}")
        return key

def normalize_iv(iv):
    iv = iv if len(iv) == 16 else iv + b"\x00" * (16 - len(iv))
    print(f"[DEBUG] Normalized IV: {iv.hex()}")
    return iv

def make_ctr(iv):
    return Counter.new(128, initial_value=int.from_bytes(iv, "big"))

def print_progress(done, total, width=60):
    if total == 0:
        return
    percent = int(done * 100 / total)
    filled = int(done * width / total)
    bar = "■" * filled + "-" * (width - filled)
    print(f"\r[{bar}] {percent}%", end="", flush=True)

def extract_kids(pssh_bytes):
    kids = []
    try:
        text = pssh_bytes.decode("utf-16-le", errors="ignore")
        start = text.find("<KID>")
        end = text.find("</KID>") + len("</KID>")
        xml = text[start:end]
        for e in ET.fromstring(f"<root>{xml}</root>").iter():
            if e.tag.lower() == "kid":
                kid_hex = uuid.UUID(bytes_le=base64.b64decode(e.text.strip())).hex
                kids.append(kid_hex)
                print(f"[DEBUG] Extracted KID from PSSH: {kid_hex}")
    except Exception as e:
        print(f"[DEBUG] Failed to extract KID: {e}")
    return kids

def extract_playready_kids(pssh_bytes):
    kids = []
    try:
        text = pssh_bytes.decode("utf-16-le", errors="ignore")
        start = text.find("<WRMHEADER")
        end = text.find("</WRMHEADER>") + len("</WRMHEADER>")
        root = ET.fromstring(text[start:end])
        for e in root.iter():
            e.tag = e.tag.split("}", 1)[-1]
        for kid_elem in root.findall(".//KID"):
            k = uuid.UUID(bytes_le=base64.b64decode(kid_elem.text.strip())).hex
            kids.append(k)
    except Exception as e:
        print(f"[DEBUG] Failed to extract PlayReady KIDs: {e}")
    return kids

def print_playready_kids(kids):
    print("[*] PlayReady PSSH KIDs found:")
    for i, k in enumerate(kids, 1):
        print(f" [{i}] {k}")

def decrypt(key_map, inp, out):
    print("[*] CENC streaming decrypt started")
    total_bytes = 0
    done_bytes = 0

    print("[DEBUG] PASS 1: Scanning for total mdat size...")
    inp.seek(0)
    while True:
        try:
            box = Box.parse_stream(inp)
            print(f"[DEBUG] Found box: {box.type.decode()}")
        except Exception:
            break
        if box.type == b"mdat":
            total_bytes += box.size - 8
            print(f"[DEBUG] Adding mdat size: {box.size - 8}, total_bytes={total_bytes}")

    print("[DEBUG] PASS 2: Starting decryption...")
    inp.seek(0)
    out.write(build_ftyp())

    keys_in_file = []
    sample_queue = deque()
    entry_queue = deque()

    while True:
        try:
            box = Box.parse_stream(inp)
            print(f"[DEBUG] Parsing box: {box.type.decode()}")
        except Exception:
            break

        if box.type == b"pssh":
            kids = extract_kids(box.data)
            for kid in kids:
                keys_in_file.append(kid.lower())
                print(f"[*] Found CENC KID: {kid}")
            pr_kids = extract_playready_kids(box.data)
            if pr_kids:
                print_playready_kids(pr_kids)
            continue

        for stsd in BoxUtil.find(box, b"stsd"):
            for entry in stsd.entries:
                if hasattr(entry, "sinf"):
                    print(f"[DEBUG] Removing 'sinf' from sample entry")
                    del entry.sinf

        if box.type == b"moof":
            print("[DEBUG] Processing moof box")
            for traf in BoxUtil.find(box, b"traf"):
                for trun in BoxUtil.find(traf, b"trun"):
                    if hasattr(trun, "sample_sizes"):
                        for sz in trun.sample_sizes:
                            sample_queue.append(sz)
                            print(f"[DEBUG] Added sample size: {sz}")
                    elif hasattr(trun, "sample_size"):
                        count = getattr(trun, "sample_count", 1)
                        for _ in range(count):
                            sample_queue.append(trun.sample_size)
                            print(f"[DEBUG] Added repeated sample size: {trun.sample_size}")
                for senc in BoxUtil.find(traf, b"senc"):
                    for entry in senc.entries:
                        entry_queue.append(entry)
                        print(f"[DEBUG] Added senc entry with IV: {entry.iv.hex()}")
            out.write(Box.build(box))
            continue

        if box.type == b"mdat":
            print(f"[DEBUG] Processing mdat box of size {box.size}")
            if not keys_in_file:
                print("\n[-] No key available for decryption!")
                out.write(struct.pack(">I4s", box.size, b"mdat"))
                out.write(inp.read(box.size - 8))
                continue

            key = key_map.get(keys_in_file[0])
            if key is None:
                print(f"\n[-] No matching key for KID {keys_in_file[0]}")
                return

            out.write(struct.pack(">I4s", box.size, b"mdat"))

            for sz in list(sample_queue):
                if not entry_queue:
                    data = inp.read(sz)
                    out.write(data)
                    done_bytes += len(data)
                    print_progress(done_bytes, total_bytes)
                    continue

                senc = entry_queue.popleft()
                iv = normalize_iv(senc.iv)
                cipher = AES.new(key, AES.MODE_CTR, counter=make_ctr(iv))

                remaining = sz
                if hasattr(senc, "subsamples") and senc.subsamples:
                    for clear_sz, enc_sz in senc.subsamples:
                        if clear_sz:
                            out.write(inp.read(clear_sz))
                            remaining -= clear_sz
                        if enc_sz:
                            enc_data = inp.read(enc_sz)
                            out.write(cipher.decrypt(enc_data))
                            remaining -= enc_sz
                else:
                    data = inp.read(remaining)
                    out.write(cipher.decrypt(data))
                    remaining = 0

                done_bytes += sz
                print_progress(done_bytes, total_bytes)

            sample_queue.clear()
            continue

        if box.type != b"ftyp":
            out.write(Box.build(box))

    print("\n[+] Decryption complete.")

def build_ftyp():
    return Box.build(dict(
        type=b"ftyp",
        major_brand=b"isom",
        minor_version=1,
        compatible_brands=[b"isom", b"iso6", b"dash"]
    ))

def simple_playready_decrypt(aes_key, expected_kid, inp, out):
    print("[*] Starting streaming decryption")
    print(f"[*] AES KEY : {aes_key.hex()}")
    print(f"[*] CLI KID : {expected_kid}")

    while True:
        data = inp.read(1024 * 1024)
        if not data:
            break
        out.write(data)
    print("[+] Simple decrypt finished")

def parse_kid_key(v):
    kid, key = v.split(":")
    return kid.lower(), binascii.unhexlify(key)

def main():
    ap = argparse.ArgumentParser("CENC MP4 decryptor (Python)")
    ap.add_argument("-k", "--key", action="append", required=True, type=parse_kid_key)
    ap.add_argument("-i", "--input", required=True, type=argparse.FileType("rb"))
    ap.add_argument("-o", "--output", required=True, type=argparse.FileType("wb"))
    args = ap.parse_args()

    km = KeyMap()
    for kid, key in args.key:
        km.add(kid, key)

    decrypt(km, args.input, args.output)

if __name__ == "__main__":
    main()
