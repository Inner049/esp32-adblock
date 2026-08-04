#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [out.bin] [src ...]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Pro) ~= 200k domains: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt
"""
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots (~250k domain budget):
# ads + trackers + malware, WhatsApp/social keep working. ~140k domains / 0.67 MB.
# Want more (up to ~250k)? swap light.txt -> pro.txt is 370k and ONLY fits the
# single-app (no-OTA) partition table.
DEFAULT_SOURCES = [
    # 1. Base list (very safe, zero false positives)
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    # 2. AdGuard DNS Filter (Aggressive ad blocking designed specifically for DNS sinkholes)
    'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt',
    # 3. Official AdGuard Ukrainian Filter (strictly UA/CIS ad networks)
    'https://filters.adtidy.org/extension/ublock/filters/23.txt'
]

WHITELIST_SOURCES = [
    # anudeepND's famous whitelist to unbreak common legitimate sites and services
    'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt',
    'https://raw.githubusercontent.com/AdguardTeam/AdguardSDNSFilter/master/Filters/exclusions.txt'
]

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower()
    if d.startswith('||'):
        d = d[2:]
    if d.endswith('^'):
        d = d[:-1]
    d = d.lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    args = sys.argv[1:]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains = set()
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            print(f'  !! skipped {src}: {e}', file=sys.stderr); continue
        for line in data.splitlines():
            # Remove comments and adblock modifiers like $third-party
            line = line.split('#', 1)[0].split('$', 1)[0].split('!', 1)[0].strip()
            
            # Ignore standard adblock exceptions and path-based rules
            if not line or line.startswith('@@') or '/' in line or '=' in line or '?' in line:
                continue
                
            parts = line.split()
            if not parts:
                continue
                
            d = parts[1] if len(parts) >= 2 and parts[0] in ('0.0.0.0','127.0.0.1','::1','::') \
                else parts[0]
                
            if d:
                d = norm(d)
                # Ensure it's a valid clean domain
                if '.' in d and ' ' not in d and '*' not in d and ':' not in d:
                    domains.add(d)

    if not domains:
        print("ERROR: No domains collected! Aborting to protect existing blocklist.", file=sys.stderr)
        sys.exit(1)

    # Process whitelists to ensure useful sites are never blocked
    whitelist_domains = set()
    for src in WHITELIST_SOURCES:
        try:
            data = read_source(src)
        except Exception as e:
            print(f'  !! skipped whitelist {src}: {e}', file=sys.stderr); continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].split('$', 1)[0].split('!', 1)[0].strip()
            if not line or line.startswith('@@') or '/' in line or '=' in line or '?' in line:
                continue
            parts = line.split()
            if not parts:
                continue
            d = parts[1] if len(parts) >= 2 and parts[0] in ('0.0.0.0','127.0.0.1','::1','::') else parts[0]
            if d:
                d = norm(d)
                if '.' in d and ' ' not in d and '*' not in d and ':' not in d:
                    whitelist_domains.add(d)
    
    # Also add specific manual whitelist domains if needed
    manual_whitelist = {'olx.ua', 'rozetka.com.ua', 'rozetka.ua'}
    whitelist_domains.update(manual_whitelist)

    # Remove whitelisted domains from the blocklist
    domains.difference_update(whitelist_domains)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()
