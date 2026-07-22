from dataclasses import dataclass, field

CONFIDENCE_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


@dataclass
class SubdomainResult:
    host: str
    source: str
    ip: str | None = None
    confidence: str = "medium"
    metadata: dict = field(default_factory=dict)


@dataclass
class AggregatedResult:
    host: str
    ips: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    confidence: str = "low"
    metadata: dict = field(default_factory=dict)

    def add(self, result: SubdomainResult) -> None:
        self.sources.add(result.source)
        if result.ip:
            self.ips.add(result.ip)
        if CONFIDENCE_RANK.get(result.confidence, 0) > CONFIDENCE_RANK.get(self.confidence, 0):
            self.confidence = result.confidence
        if result.metadata:
            self.metadata.setdefault(result.source, []).append(result.metadata)
