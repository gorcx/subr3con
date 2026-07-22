from __future__ import annotations

import os
import queue
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address
from pathlib import Path

import dns.exception
import dns.resolver

from .base import Source, is_valid_hostname

TIMING_PROFILES = {
    1: {"threads": 10, "timeout": 2.0, "lifetime": 4.0},
    2: {"threads": 20, "timeout": 1.5, "lifetime": 3.0},
    3: {"threads": 40, "timeout": 1.0, "lifetime": 2.0},
    4: {"threads": 80, "timeout": 0.8, "lifetime": 1.6},
    5: {"threads": 150, "timeout": 0.5, "lifetime": 1.0},
}
MUTATION_PREFIXES = ("dev", "test", "staging", "prod")
MUTATION_SUFFIXES = ("1", "2", "-dev", "-test", "-staging", "-prod")


class BruteforceSource(Source):
    name = "bruteforce"
    confidence = "high"
    foreground = True

    def run(self):
        wordlist = Path(os.environ.get("SUBR3CON_WORDLIST", default_wordlist()))
        if not wordlist.exists():
            return self.skip(f"wordlist not found: {wordlist}")

        max_names = max(0, int(os.environ.get("SUBR3CON_BRUTE_MAX_NAMES", os.environ.get("SUBBRUTE_MAX_NAMES", 0))))
        timing = int(os.environ.get("SUBR3CON_TIMING", 3))
        if timing not in TIMING_PROFILES:
            timing = 3
        timing_profile = TIMING_PROFILES[timing]
        threads = max(1, int(os.environ.get("SUBR3CON_BRUTE_THREADS", timing_profile["threads"])))
        dns_timeout = max(
            0.1,
            float(os.environ.get("SUBR3CON_DNS_TIMEOUT", os.environ.get("SUBBRUTE_DNS_TIMEOUT", timing_profile["timeout"]))),
        )
        dns_lifetime = max(
            dns_timeout,
            float(os.environ.get("SUBR3CON_DNS_LIFETIME", os.environ.get("SUBBRUTE_DNS_LIFETIME", timing_profile["lifetime"]))),
        )
        progress_interval = max(0.1, float(os.environ.get("SUBR3CON_PROGRESS_INTERVAL", 10)))
        nameservers = load_resolvers(os.environ.get("SUBR3CON_RESOLVERS") or os.environ.get("SUBR3CON_NAMESERVERS", "system"))
        verify_resolvers = os.environ.get("SUBR3CON_VERIFY_RESOLVERS", "1").lower() in {"1", "true", "yes", "on"}
        resolver_max = max(1, int(os.environ.get("SUBR3CON_MAX_RESOLVERS", 50)))
        if nameservers and verify_resolvers:
            candidate_count = len(nameservers)
            nameservers = validate_resolvers(nameservers, timeout=min(dns_timeout, 2.0), max_resolvers=resolver_max)
            self.debug(f"resolver check healthy={len(nameservers)}/{candidate_count}")
            if nameservers:
                self.debug(f"resolver pool fastest-first={','.join(nameservers)}")
            if not nameservers:
                self.debug("no bundled/custom resolver answered; falling back to system DNS")

        wildcard_enabled = os.environ.get("SUBR3CON_WILDCARD_CHECK", "1").lower() in {"1", "true", "yes", "on"}
        wildcard_probes = max(1, int(os.environ.get("SUBR3CON_WILDCARD_PROBES", 3)))
        wildcard_signatures = (
            detect_wildcard(
                self.context.domain,
                nameservers,
                timeout=dns_timeout,
                lifetime=dns_lifetime,
                probe_count=wildcard_probes,
            )
            if wildcard_enabled
            else set()
        )
        if wildcard_signatures:
            self.debug(f"wildcard DNS detected signatures={len(wildcard_signatures)}")

        names = load_names(wordlist, max_names=max_names)
        mutations_enabled = os.environ.get("SUBR3CON_MUTATIONS", "0").lower() in {"1", "true", "yes", "on"}
        mutation_max = max(0, int(os.environ.get("SUBR3CON_MUTATION_MAX", 500)))
        mutations = generate_mutations(names, mutation_max) if mutations_enabled else []

        q: queue.Queue[str] = queue.Queue()
        for name in [*names, *mutations]:
            host = qualify_name(name, self.context.domain)
            if host:
                q.put(host)

        total = q.qsize()
        resolver_label = "system" if not nameservers else str(len(nameservers))
        self.debug(
            f"queued={total} names={len(names)} mutations={len(mutations)} timing=T{timing} threads={threads} timeout={dns_timeout}s "
            f"lifetime={dns_lifetime}s resolvers={resolver_label}"
        )
        results = []
        seen = set()
        lock = threading.Lock()
        stop_event = threading.Event()
        stats = {"processed": 0, "wildcard_filtered": 0, "errors": 0}

        def worker(worker_index: int):
            resolver = dns.resolver.Resolver()
            resolver.timeout = dns_timeout
            resolver.lifetime = dns_lifetime
            if nameservers:
                resolver.nameservers = [nameservers[worker_index % len(nameservers)]]
            while not stop_event.is_set():
                try:
                    host = q.get(False)
                except queue.Empty:
                    return
                try:
                    addresses = resolve_addresses(resolver, host)
                    if not addresses:
                        continue
                    if is_wildcard_answer(addresses, wildcard_signatures):
                        with lock:
                            stats["wildcard_filtered"] += 1
                        continue
                    ip = sorted(addresses)[0] if addresses else None
                    result = self.result(host, ip=ip)
                    if result:
                        with lock:
                            if result.host not in seen:
                                seen.add(result.host)
                                results.append(result)
                except Exception:
                    with lock:
                        stats["errors"] += 1
                finally:
                    with lock:
                        stats["processed"] += 1
                    q.task_done()

        workers = [threading.Thread(target=worker, args=(index,), daemon=True) for index in range(max(1, threads))]
        for thread in workers:
            thread.start()

        last_progress = [time.time()]

        def report_progress():
            if self.context.debug and time.time() - last_progress[0] >= progress_interval:
                self.debug(
                    f"processed={stats['processed']}/{total} found={len(results)} "
                    f"wildcard_filtered={stats['wildcard_filtered']} errors={stats['errors']}"
                )
                last_progress[0] = time.time()

        interrupted = wait_for_workers(workers, stop_event, report_progress)
        if interrupted:
            self.debug(f"interrupted processed={stats['processed']}/{total} found={len(results)}")

        join_deadline = time.monotonic() + max(1.0, dns_lifetime + 0.5)
        for thread in workers:
            thread.join(max(0.0, join_deadline - time.monotonic()))
        self.debug(
            f"finished processed={stats['processed']}/{total} found={len(results)} "
            f"wildcard_filtered={stats['wildcard_filtered']} errors={stats['errors']}"
        )
        return results


def default_wordlist() -> str:
    return str(Path(__file__).resolve().parents[1] / "data" / "names.txt")


def default_resolvers() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "resolvers.txt"


def load_resolvers(value: str) -> list[str]:
    value = (value or "system").strip()
    if not value or value.lower() == "system":
        return []
    if value.lower() == "bundled":
        return read_resolver_file(default_resolvers())

    candidate = Path(value)
    if candidate.exists():
        return read_resolver_file(candidate)

    return list(dict.fromkeys(item.strip() for item in value.split(",") if is_resolver_address(item.strip())))


def read_resolver_file(path: Path) -> list[str]:
    resolvers = []
    seen = set()
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            resolver = line.strip()
            if is_resolver_address(resolver) and resolver not in seen:
                seen.add(resolver)
                resolvers.append(resolver)
    return resolvers


def is_resolver_address(value: str) -> bool:
    if not value or value.startswith("#"):
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def validate_resolvers(
    resolvers: list[str],
    timeout: float = 1.0,
    max_resolvers: int = 50,
    probe_host: str = "example.com",
) -> list[str]:
    candidates = list(dict.fromkeys(resolver for resolver in resolvers if is_resolver_address(resolver)))
    if not candidates or max_resolvers <= 0:
        return []

    healthy = []
    worker_count = min(20, len(candidates))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(probe_resolver, resolver, timeout, probe_host): resolver for resolver in candidates}
        for future in as_completed(futures):
            latency = future.result()
            if latency is not None:
                healthy.append((latency, futures[future]))

    healthy.sort()
    return [resolver for _, resolver in healthy[:max_resolvers]]


def probe_resolver(resolver_address: str, timeout: float, probe_host: str) -> float | None:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [resolver_address]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    started = time.monotonic()
    try:
        answer = resolver.resolve(probe_host, "A")
    except Exception:
        return None
    return time.monotonic() - started if answer else None


def detect_wildcard(
    domain: str,
    nameservers: list[str],
    timeout: float,
    lifetime: float,
    probe_count: int = 3,
) -> set[frozenset[str]]:
    signatures = set()
    for index in range(probe_count):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = lifetime
        if nameservers:
            resolver.nameservers = [nameservers[index % len(nameservers)]]
        host = f"subr3con-{secrets.token_hex(8)}.{domain}"
        try:
            addresses = resolve_addresses(resolver, host)
        except Exception:
            continue
        if addresses:
            signatures.add(frozenset(addresses))
    return signatures


def resolve_addresses(resolver, host: str) -> set[str]:
    addresses = set()
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, record_type) if hasattr(resolver, "resolve") else resolver.query(host, record_type)
        except dns.resolver.NXDOMAIN:
            break
        except dns.exception.DNSException:
            continue
        addresses.update(record.to_text() for record in answer)
    return addresses


def is_wildcard_answer(addresses: set[str], signatures: set[frozenset[str]]) -> bool:
    return bool(addresses and frozenset(addresses) in signatures)


def wait_for_workers(workers, stop_event: threading.Event, progress_callback=None, poll_interval: float = 0.2) -> bool:
    try:
        while any(worker.is_alive() for worker in workers):
            if progress_callback:
                progress_callback()
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        stop_event.set()
        return True
    return False


def load_names(wordlist: Path, max_names: int = 0) -> list[str]:
    seen = set()
    names = []
    with wordlist.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            name = line.strip().split(",")[0].lower()
            if not name or name.startswith("#") or name in seen or not is_valid_hostname(name):
                continue
            seen.add(name)
            names.append(name)
            if max_names > 0 and len(names) >= max_names:
                break

    return names


def qualify_name(name: str, domain: str) -> str | None:
    if name == domain:
        return None
    host = name if name.endswith(f".{domain}") else f"{name}.{domain}"
    return host if is_valid_hostname(host) else None


def generate_mutations(names: list[str], max_mutations: int = 500) -> list[str]:
    if max_mutations <= 0:
        return []

    existing = set(names)
    mutations = []
    for name in names:
        if "." in name or not name or name[-1].isdigit():
            continue
        candidates = [*(f"{name}{suffix}" for suffix in MUTATION_SUFFIXES)]
        candidates.extend(f"{prefix}-{name}" for prefix in MUTATION_PREFIXES)
        for candidate in candidates:
            if len(candidate) > 63 or candidate in existing:
                continue
            existing.add(candidate)
            mutations.append(candidate)
            if len(mutations) >= max_mutations:
                return mutations
    return mutations
