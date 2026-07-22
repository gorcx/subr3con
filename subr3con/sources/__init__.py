from .bruteforce import BruteforceSource
from .c99 import C99Source
from .crtsh import CrtshSource
from .ctlogs import CertificateTransparencySource
from .dnsdumpster import DNSDumpsterSource
from .netcraft import NetcraftSource
from .virustotal import VirusTotalSource

SOURCE_REGISTRY = {
    "virustotal": VirusTotalSource,
    "dnsdumpster": DNSDumpsterSource,
    "crtsh": CrtshSource,
    "netcraft": NetcraftSource,
    "c99": C99Source,
    "ctlogs": CertificateTransparencySource,
    "bruteforce": BruteforceSource,
}
