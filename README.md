# Subr3con

Subr3con is a modern Python subdomain reconnaissance tool inspired by Sublist3r.

Use Subr3con only on domains you own or are explicitly authorized to assess.

## Installation

For regular use, install Subr3con as an isolated command-line application with
`pipx`:

```bash
pipx install git+https://github.com/gorcx/subr3con.git
subr3con --help
```

The `subr3con` command is then available directly from any directory. Python
3.10 or newer is required.

For development from a cloned repository, use an editable virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
subr3con --help
```

## Quick Start

```bash
subr3con -d example.com -pF
subr3con -d example.com -pX 1000 --debug
subr3con -d example.com --sources virustotal,dnsdumpster,c99 -s -c
```

Replace `example.com` with a domain you own or have explicit permission to
assess. By default, Subr3con prints only subdomains.

Results are written to standard output while diagnostics are written to standard error, so debug mode remains safe to pipe:

```bash
subr3con -d example.com -pX 5000 --debug > domains.txt
subr3con -d example.com -pX 5000 --debug > domains.txt 2> scan-debug.log
```

## Profiles

- `-pF`, `--profile-fast`: `virustotal,dnsdumpster,ctlogs,netcraft,c99`
- `-pB [N]`, `--profile-brute [N]`: DNS bruteforce only, optionally limited to top N names
- `-pX [N]`, `--profile-mixed [N]`: fast profile plus bruteforce, optionally limited to top N names

`-pA` is reserved for a future profile that may include best-effort search
engines. The current complete profile is `-pX`.

You can bypass profiles with:

```bash
subr3con -d example.com --sources virustotal,c99,crtsh
```

## Output

```bash
subr3con -d example.com -pF
subr3con -d example.com -pF -i -s -c
subr3con -d example.com -pF --format json -o results.json
subr3con -d example.com -pF --format csv -o results.csv
subr3con -d example.com -pB 1000 --debug
subr3con -d example.com -pB 1000 -T4 --resolvers bundled
```

Options:

- `-i`, `--ip`: show IPs when available
- `-s`, `--source`: show sources
- `-c`, `--confidence`: show confidence
- `--format {txt,json,csv}`: select the output format
- `-o`, `--output`: write results to a file
- `--debug`: show detailed source diagnostics on standard error
- `--sequential`: run sources one by one
- `--no-summary`: hide the final source summary

The host is always included as the first TXT field, so it does not require a
separate option.

With `-i`, every final host is resolved after source aggregation. Both IPv4 and IPv6 addresses are collected, including for hosts
found only through passive sources. Use `--ip-threads` and `--ip-timeout` to tune this final DNS pass.

## Environment

Create `.env` next to this README:

```env
DNSDUMPSTER_API_KEY=
VIRUSTOTAL_API_KEY=

VIRUSTOTAL_API_DELAY=16
VIRUSTOTAL_MAX_PAGES=0

C99_SCAN_DATE=
C99_INCLUDE_HIDDEN=1
C99_LOOKBACK_DAYS=14
C99_DATE_CACHE_TTL=86400

SUBR3CON_CT_PROVIDER=auto
CERTSPOTTER_API_KEY=
CERTSPOTTER_MAX_PAGES=1

SUBR3CON_HTTP_RETRIES=2
SUBR3CON_HTTP_BACKOFF=0.5
SUBR3CON_HTTP_RETRY_MAX_WAIT=8
SUBR3CON_HTTP_CACHE=1
SUBR3CON_CACHE_TTL=900
SUBR3CON_CACHE_DIR=

SUBR3CON_BRUTE_MAX_NAMES=1000
SUBR3CON_TIMING=3
# SUBR3CON_BRUTE_THREADS=40
# SUBR3CON_DNS_TIMEOUT=1
# SUBR3CON_DNS_LIFETIME=2
SUBR3CON_PROGRESS_INTERVAL=10
# SUBR3CON_WORDLIST=/path/to/names.txt
SUBR3CON_RESOLVERS=system
SUBR3CON_VERIFY_RESOLVERS=1
SUBR3CON_MAX_RESOLVERS=50
SUBR3CON_WILDCARD_CHECK=1
SUBR3CON_WILDCARD_PROBES=3
SUBR3CON_MUTATIONS=0
SUBR3CON_MUTATION_MAX=500
```

You can override `SUBR3CON_BRUTE_MAX_NAMES` from the command line:

```bash
subr3con -d example.com -pB 1000
subr3con -d example.com -pX 5000
subr3con -d example.com -pB --brute-max 1000
```

The bundled wordlist is read in file order. The top-N limit therefore selects exactly the first N unique entries.

Bruteforce timing can be adjusted like Nmap-style templates:

```bash
subr3con -d example.com -pB 1000 -T1  # slower, gentler
subr3con -d example.com -pB 1000 -T3  # default
subr3con -d example.com -pB 1000 -T5  # fastest/noisiest
```

`-T1` through `-T5` control DNS concurrency and timeouts only. They do not change which names are tested. Explicit command-line
options take priority over `.env` settings.

An optional lightweight second pass generates common numeric and environment variants after every selected wordlist entry has
been queued:

```bash
subr3con -d example.com -pB 1000 -T3 --mutations
subr3con -d example.com -pB 1000 -T3 --mutations --mutation-max 250
```

Resolver options:

```bash
--resolvers system                 # default, use system DNS resolver
--resolvers bundled                # use bundled resolvers.txt
--resolvers 1.1.1.1,8.8.8.8        # explicit resolvers
--resolvers /path/to/resolvers.txt # custom resolver file
```

Bundled and custom resolvers are checked concurrently before the scan, ordered by response time, and distributed across DNS
workers. If none answer, Subr3con falls back to the system resolver. Use `--resolver-max N` to cap the healthy pool or
`--no-resolver-check` only when the supplied resolvers have already been verified.

The bundled pool contains the standard unfiltered services from Cloudflare and Google, Cisco OpenDNS, and Quad9's no-threat-
blocking service. Resolver availability is still verified locally before every bruteforce run.

Subr3con also probes random labels before bruteforcing. Answers matching an observed wildcard DNS signature are discarded. The
check can be disabled with `--no-wildcard-check`, but this may produce many false positives on wildcard-enabled domains.

## Debug

```bash
subr3con -d example.com -pF --debug --sequential
```

Debug messages, source errors, and bruteforce progress do not contaminate TXT, JSON, or CSV result output.

A compact source summary is written to standard error by default. It reports status, result count, duration, HTTP requests, and
cache hits. Use `--no-summary` for a completely quiet diagnostic stream.

Transient HTTP failures are retried with exponential backoff. Successful responses and recent not-found lookups are cached in
the operating system's temporary directory for 15 minutes by default; API credentials are represented only by a one-way cache-key
hash and are never written into cache files.

The `ctlogs` source uses Shodan's public Certificate Transparency API first and falls back to Cert Spotter when Shodan returns no
usable names. Set `SUBR3CON_CT_PROVIDER=all` to query and merge both. Unauthenticated Cert Spotter use is rate limited, so only one
page is requested by default. The legacy `crtsh` source remains available through `--sources crtsh`, but is no longer part of `-pF`.

## Credits

Subr3con is an independent implementation inspired by
[Sublist3r](https://github.com/aboul3la/Sublist3r), created by Ahmed Aboul-Ela.
Its architecture, source integrations, bruteforce engine, and ordered wordlist
were developed specifically for Subr3con.

## License

Subr3con is released under the [MIT License](LICENSE).
