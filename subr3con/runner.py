from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .models import AggregatedResult
from .sources import SOURCE_REGISTRY
from .sources.base import SourceContext


@dataclass
class SourceRunStatus:
    name: str
    status: str
    duration: float
    result_count: int
    request_count: int = 0
    cache_hits: int = 0
    error: str | None = None


def run_sources(
    domain: str,
    source_names: list[str],
    timeout: float = 25,
    debug: bool = False,
    sequential: bool = False,
    summary: bool = False,
):
    context = SourceContext(domain=domain, timeout=timeout, debug=debug)
    sources = [SOURCE_REGISTRY[name](context) for name in source_names]
    aggregate: dict[str, AggregatedResult] = {}
    statuses: dict[str, SourceRunStatus] = {}

    def run_source(source):
        started = time.time()
        if debug:
            print(f"[debug:{source.name}] start", file=sys.stderr, flush=True)
        try:
            results = source.run()
            status = classify_source_status(source, results)
            if debug:
                print(
                    f"[debug:{source.name}] finish {time.time() - started:.2f}s results={len(results)}",
                    file=sys.stderr,
                    flush=True,
                )
            return results, SourceRunStatus(
                name=source.name,
                status=status,
                duration=time.time() - started,
                result_count=len(results),
                request_count=source.request_count,
                cache_hits=source.cache_hits,
                error=source.last_error or source.skipped_reason,
            )
        except Exception as exc:
            if debug:
                print(
                    f"[debug:{source.name}] failed {time.time() - started:.2f}s error={exc}",
                    file=sys.stderr,
                    flush=True,
                )
            return [], SourceRunStatus(
                name=source.name,
                status="error",
                duration=time.time() - started,
                result_count=0,
                request_count=source.request_count,
                cache_hits=source.cache_hits,
                error=str(exc),
            )
        finally:
            source.session.close()

    if sequential:
        for source in sources:
            results, status = run_source(source)
            merge_results(aggregate, results)
            statuses[source.name] = status
    else:
        foreground_sources = [source for source in sources if source.foreground]
        background_sources = [source for source in sources if not source.foreground]
        with ThreadPoolExecutor(max_workers=len(background_sources) or 1) as executor:
            futures = {executor.submit(run_source, source): source.name for source in background_sources}
            for source in foreground_sources:
                results, status = run_source(source)
                merge_results(aggregate, results)
                statuses[source.name] = status
            for future in as_completed(futures):
                results, status = future.result()
                merge_results(aggregate, results)
                statuses[status.name] = status

    if summary:
        print_source_summary(source_names, statuses)

    return sorted(aggregate.values(), key=lambda item: item.host.split(".")[::-1])


def merge_results(aggregate: dict[str, AggregatedResult], results) -> None:
    for result in results:
        aggregate.setdefault(result.host, AggregatedResult(host=result.host)).add(result)


def classify_source_status(source, results) -> str:
    if source.skipped_reason:
        return "skipped"
    if source.timed_out and not results:
        return "timeout"
    if source.last_error and results:
        return "partial"
    if source.last_error:
        return "error"
    return "ok" if results else "empty"


def print_source_summary(source_names: list[str], statuses: dict[str, SourceRunStatus]) -> None:
    print("[summary] source status results time requests cache", file=sys.stderr)
    for name in source_names:
        status = statuses[name]
        message = (
            f"[summary] {status.name} {status.status} {status.result_count} {status.duration:.2f}s "
            f"{status.request_count} {status.cache_hits}"
        )
        if status.error:
            message += f" error={status.error}"
        print(message, file=sys.stderr)
