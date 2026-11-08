# Hasr

Hasr inventories the cryptography of TLS endpoints and reports it against
**SAMA Circular No. 482021280** on quantum-computing risk. The name comes from
«حصر» (*hasr*), the word Clause 2 of the circular uses for inventorying
cryptographic assets.

![Hasr report: the header with its overview cards, and the Clause 2a priority table](docs/report.png)

*Two parts of one report, from the test lab with the sample mapping: the header
with its overview cards, and the Clause 2a priority table.*

## Why

Traffic protected today by RSA, Diffie-Hellman or elliptic-curve key exchange
can be recorded now and decrypted once a large enough quantum computer exists
("harvest now, decrypt later"). SAMA Circular No. 482021280 (27 August 2026)
requires financial institutions to ensure accurate and comprehensive procedures
for inventorying and classifying all their cryptographic assets by the end of
Q4 2026. An inventory built from interviews and spreadsheets cannot prove it is
complete, and it goes out of date as soon as a system changes.

## What Hasr does today

- `hasr scan` connects to each TLS endpoint you list and records the cryptography it accepts.
- `hasr report` joins a scan with a mapping file (systems, owners, data
  classification) and writes an HTML report, with its JSON, organised by the
  circular's clauses.

| Clause | What Hasr provides today | What stays with the institution |
|---|---|---|
| **1** Enterprise risk assessment (due end of Q1 2027) | Technical input: key-exchange status, legacy findings and Mosca margin per endpoint | The assessment itself; operational, legal, regulatory, strategic and workforce risks; the action plans |
| **2a** Data, systems and services; sensitivity and migration priority (due end of Q4 2026) | TLS discovery; links to systems and owners from the mapping file; migration priority by Mosca's inequality | A complete, correct target list and mapping data |
| **2b** Crypto-agility, constraints, third parties | Evidence from the scan (TLS 1.3, hybrid key exchange); constraints and third parties from the mapping file | The crypto-agility assessment: Hasr's rating is not built yet |
| **2** Completeness of the procedures | A completeness figure; lists of targets that need owner input, were mapped but not scanned, or could not be assessed; the scanner's stated limits | Cryptography outside TLS endpoints |
| **3** Plans to reach the required crypto-agility | A recommended action for each finding, in priority order | The plans and initiatives |
| **4** Standing monitoring by committees | Repeatable scans; each scan's JSON can be kept as evidence | The committees' agenda and escalation. Tracking changes between scans is not built yet |

Reports quote an unofficial English translation of the circular; the official
text is the Arabic original.

## How it works

`hasr scan` runs seven ordinary handshakes per target, each with a different
offer: Go's default; hybrid key exchange only (X25519MLKEM768); classical groups
only; TLS 1.2 at most; TLS 1.1 only; TLS 1.0 only; and TLS 1.2 with only RSA key
transport, 3DES and RC4 suites. From the answers it sets two independent fields:
`key_exchange` (hybrid, classical or unknown) and `legacy` (yes, no or unknown).
A handshake that got no answer never counts as "not supported".

`hasr report` ranks assets by Mosca's inequality, X + Y > Z: X is how long the
data must stay confidential, Y how long migration takes, and Z the time until the
quantum threat or a regulatory deadline. The default policy sets Z to 31 December
2030 (the NIST IR 8547 deprecation date and the EU roadmap deadline for high-risk
use cases), with its source printed in the report. [DECISIONS.md](DECISIONS.md)
records every rule and the reason for it.

## Quick start

Requirements: Go 1.21 or later (Go then fetches the 1.27.3 toolchain pinned in
`go.mod`) and, for the test lab, OpenSSL 3.5.6 or later.

```sh
go build -o hasr .
./testlab/start.sh        # three TLS test servers on 127.0.0.1:8443-8445
./hasr scan -table 127.0.0.1:8443 127.0.0.1:8444 127.0.0.1:8445
```

```
TARGET          KEX        LEGACY  VERSIONS     DEFAULT GETS            CERT KEYS    TRUSTED
127.0.0.1:8443  hybrid     no      1.2 1.3      TLS 1.3 X25519MLKEM768  ECDSA P-256  0/1
127.0.0.1:8444  classical  no      1.2 1.3      TLS 1.3 x25519          ECDSA P-256  0/1
127.0.0.1:8445  classical  yes     1.0 1.1 1.2  TLS 1.2 x25519          RSA 2048     0/1
```

A note and one detail block per target follow the table. Without `-table`,
`hasr scan` writes JSON. Then the report:

```sh
./hasr scan --targets testlab/mapping.csv > scan.json
./hasr report --scan scan.json --map testlab/mapping.csv   # writes hasr-report.html and hasr-report.json
./testlab/stop.sh
```

`testlab/mapping.csv` is fictional sample data. Two of its entries have no
server behind them, so the report shows the "not assessed" section and
`hasr scan` exits with status 1 (expected). `testlab/start.sh` uses the `openssl` on your
`PATH`; set `OPENSSL=/path/to/openssl` to use another.

## Mapping and policy files

- **Mapping CSV:** one row per `host:port`, with the columns `target, system,
  service, owner, data_classification, data_shelf_life_years, migration_years,
  third_party, constraints`. `data_classification` must be one of the policy's
  levels. `data_shelf_life_years` (X) and `migration_years` (Y) override the
  defaults for that row. When `third_party` is not `in-house` and
  `migration_years` is empty, Y stays unknown: a vendor's timeline is never guessed.
- **Policy:** [`policy/default.json`](policy/default.json) holds the classification
  levels (the Saudi NDMO levels), the default X per level, the default Y per scan
  category, and Z as a date. Every value carries its source, which the report
  prints next to it. `--policy` points to another file.

## Responsible use

- Hasr sends only standard TLS handshakes. It does not exploit, fuzz or send application data.
- Scan only systems you own or are explicitly authorised to assess.
- The test lab binds to 127.0.0.1 only.

## Limitations

- Network TLS endpoints only.
- Not tested: SSLv3, finite-field DHE, groups no probe offers, and the signature
  scheme the server uses in the handshake. Reports list these as the scanner's
  stated limits.
- 3DES and RC4 suites are offered, but a handshake using them has not yet been
  verified against a test server.
- One TLS client implementation: Go's `crypto/tls`.

## Status and roadmap

- **Built:** `hasr scan` and `hasr report`, with the report organised by the circular's clauses.
- **Next:** cloud discovery.
- **Planned:** crypto-agility rating, change tracking
  between scans, verification of 3DES and RC4 handshakes, a Markdown report, CI
  with govulncheck.
- **Later:** code scanning and other discovery layers.

## Development

```sh
go test ./...
GOTOOLCHAIN=go1.27.3 go install golang.org/x/vuln/cmd/govulncheck@latest
"$(go env GOPATH)/bin/govulncheck" ./...
```

govulncheck must be built with the project's Go version; an older build cannot
read the code. [DECISIONS.md](DECISIONS.md) records every design decision, with
its date and reason.

## License

No license yet; all rights reserved.
