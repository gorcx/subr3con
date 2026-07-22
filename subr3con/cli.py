from __future__ import annotations

import argparse
import math
import os
import re
import sys
from urllib.parse import urlsplit

from .config import PROFILES, load_dotenv
from .enrich import enrich_ips
from .output import write_results
from .runner import run_sources
from .sources import SOURCE_REGISTRY


def build_parser():
    parser = argparse.ArgumentParser(prog="subr3con", description="Modern subdomain reconnaissance.")
    parser.add_argument("-d", "--domain", required=True, help="Domain to enumerate")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("-pF", "--profile-fast", action="store_true", help="Use fast passive sources")
    selection.add_argument(
        "-pB",
        "--profile-brute",
        nargs="?",
        const=0,
        type=non_negative_int,
        metavar="N",
        help="Use bruteforce only, optionally with top N names",
    )
    selection.add_argument(
        "-pX",
        "--profile-mixed",
        nargs="?",
        const=0,
        type=non_negative_int,
        metavar="N",
        help="Use fast passive sources plus bruteforce, optionally with top N names",
    )
    selection.add_argument("--profile", choices=sorted(PROFILES), help="Named profile")
    selection.add_argument("--sources", help="Comma-separated sources. Available: " + ", ".join(sorted(SOURCE_REGISTRY)))
    parser.add_argument("-i", "--ip", action="store_true", help="Show IPs when available")
    parser.add_argument("--ip-threads", type=positive_int, default=30, help="Parallel workers used for IP enrichment")
    parser.add_argument("--ip-timeout", type=positive_float, default=2.0, help="DNS timeout for IP enrichment")
    parser.add_argument("-s", "--source", action="store_true", help="Show sources")
    parser.add_argument("-c", "--confidence", action="store_true", help="Show confidence")
    parser.add_argument("--format", choices=["txt", "json", "csv"], default="txt", help="Output format")
    parser.add_argument("-o", "--output", help="Write output to file")
    parser.add_argument("--brute-max", type=non_negative_int, help="Limit bruteforce to the top N names (0 means unlimited)")
    parser.add_argument("-T", "--timing", type=int, choices=range(1, 6), metavar="1-5", help="Bruteforce timing template")
    parser.add_argument("--brute-threads", type=positive_int, help="Override bruteforce thread count")
    parser.add_argument("--mutations", action="store_true", help="Test lightweight name mutations after the wordlist")
    parser.add_argument("--mutation-max", type=non_negative_int, help="Limit the number of generated mutation candidates")
    parser.add_argument("--resolvers", help="DNS resolvers: system, bundled, comma-separated IPs, or a file path")
    parser.add_argument("--resolver-max", type=positive_int, help="Maximum number of healthy resolvers to use")
    parser.add_argument("--no-resolver-check", action="store_true", help="Skip bundled/custom resolver health checks")
    parser.add_argument("--no-wildcard-check", action="store_true", help="Disable DNS wildcard detection")
    parser.add_argument("--timeout", type=positive_float, default=25, help="HTTP timeout per request")
    parser.add_argument("--debug", action="store_true", help="Show source diagnostics")
    parser.add_argument("--summary", action=argparse.BooleanOptionalAction, default=True, help="Show the final source summary")
    parser.add_argument("--sequential", action="store_true", help="Run sources one by one")
    return parser


def main(argv=None):
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    domain = normalize_domain(args.domain)
    if not valid_domain(domain):
        parser.error("Please provide a valid domain")

    apply_bruteforce_limit(args)
    source_names = choose_sources(args)
    unknown = [source for source in source_names if source not in SOURCE_REGISTRY]
    if unknown:
        parser.error("Unknown source(s): " + ",".join(unknown))

    results = run_sources(
        domain,
        source_names,
        timeout=args.timeout,
        debug=args.debug,
        sequential=args.sequential,
        summary=args.summary,
    )
    if args.ip:
        enrich_ips(results, threads=args.ip_threads, timeout=args.ip_timeout, debug=args.debug)
    write_results(
        results,
        fmt=args.format,
        output=args.output,
        show_ip=args.ip,
        show_source=args.source,
        show_confidence=args.confidence,
    )
    return 0


def choose_sources(args) -> list[str]:
    if args.sources:
        return list(dict.fromkeys(source.strip().lower() for source in args.sources.split(",") if source.strip()))
    if args.profile_fast:
        return PROFILES["fast"]
    if args.profile_brute is not None:
        return PROFILES["brute"]
    if args.profile_mixed is not None:
        return PROFILES["mixed"]
    if args.profile:
        return PROFILES[args.profile]
    return PROFILES["fast"]


def apply_bruteforce_limit(args) -> None:
    value = args.brute_max
    if value is None and args.profile_brute not in (None, 0):
        value = args.profile_brute
    if value is None and args.profile_mixed not in (None, 0):
        value = args.profile_mixed
    if value is not None:
        os.environ["SUBR3CON_BRUTE_MAX_NAMES"] = str(max(0, value))
    if args.timing is not None:
        for key in (
            "SUBR3CON_BRUTE_THREADS",
            "SUBR3CON_DNS_TIMEOUT",
            "SUBR3CON_DNS_LIFETIME",
            "SUBBRUTE_DNS_TIMEOUT",
            "SUBBRUTE_DNS_LIFETIME",
        ):
            os.environ.pop(key, None)
        os.environ["SUBR3CON_TIMING"] = str(args.timing)
    if args.brute_threads is not None:
        os.environ["SUBR3CON_BRUTE_THREADS"] = str(max(1, args.brute_threads))
    if args.mutations or args.mutation_max is not None:
        os.environ["SUBR3CON_MUTATIONS"] = "1"
    if args.mutation_max is not None:
        os.environ["SUBR3CON_MUTATION_MAX"] = str(max(0, args.mutation_max))
    if args.resolvers:
        os.environ["SUBR3CON_RESOLVERS"] = args.resolvers
    if args.resolver_max is not None:
        os.environ["SUBR3CON_MAX_RESOLVERS"] = str(max(1, args.resolver_max))
    if args.no_resolver_check:
        os.environ["SUBR3CON_VERIFY_RESOLVERS"] = "0"
    if args.no_wildcard_check:
        os.environ["SUBR3CON_WILDCARD_CHECK"] = "0"


def normalize_domain(value: str) -> str:
    value = value.strip()
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        return host.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return ""


def valid_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    return all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label, re.IGNORECASE) for label in labels)


def non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


if __name__ == "__main__":
    sys.exit(main())
