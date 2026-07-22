from __future__ import annotations

import csv
import json
import sys


def write_results(results, fmt="txt", output=None, show_ip=False, show_source=False, show_confidence=False):
    if output:
        handle = open(output, "w", encoding="utf-8", newline="")
        close = True
    else:
        handle = sys.stdout
        close = False
    try:
        if fmt == "json":
            write_json(results, handle)
        elif fmt == "csv":
            write_csv(results, handle)
        else:
            write_txt(results, handle, show_ip, show_source, show_confidence)
    finally:
        if close:
            handle.close()


def write_txt(results, handle, show_ip, show_source, show_confidence):
    enriched = show_ip or show_source or show_confidence
    for result in results:
        if not enriched:
            print(result.host, file=handle)
            continue
        fields = [result.host]
        if show_ip:
            fields.append(",".join(sorted(result.ips)))
        if show_source:
            fields.append(",".join(sorted(result.sources)))
        if show_confidence:
            fields.append(result.confidence)
        print("\t".join(fields), file=handle)


def write_json(results, handle):
    data = [
        {
            "host": result.host,
            "ips": sorted(result.ips),
            "sources": sorted(result.sources),
            "confidence": result.confidence,
            "metadata": result.metadata,
        }
        for result in results
    ]
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")


def write_csv(results, handle):
    writer = csv.DictWriter(handle, fieldnames=["host", "ips", "sources", "confidence"])
    writer.writeheader()
    for result in results:
        writer.writerow(
            {
                "host": result.host,
                "ips": ",".join(sorted(result.ips)),
                "sources": ",".join(sorted(result.sources)),
                "confidence": result.confidence,
            }
        )
