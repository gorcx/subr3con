from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver


def enrich_ips(results, threads: int = 30, timeout: float = 2.0, debug: bool = False) -> None:
    if not results:
        return

    resolved = 0
    worker_count = min(max(1, threads), len(results))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(resolve_host_ips, result.host, timeout): result for result in results}
        for future in as_completed(futures):
            addresses = future.result()
            if addresses:
                futures[future].ips.update(addresses)
                resolved += 1

    if debug:
        print(f"[debug:ip] resolved={resolved}/{len(results)}", file=sys.stderr, flush=True)


def resolve_host_ips(host: str, timeout: float = 2.0) -> set[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    addresses = set()
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, record_type)
        except Exception:
            continue
        addresses.update(record.to_text() for record in answer)
    return addresses
