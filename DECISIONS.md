# Decisions

Each entry: date, decision, reason. Only decided items are built.

## 2026-11-08 — Scope (from the project brief)

- **Decision:** Version 1 covers two discovery layers: network and cloud. Code scanning and other layers come after the competition.
- **Reason:** Fixed in the project brief before planning started.

## 2026-11-08 — Step 1: TLS probe

### Language and toolchain

- **Decision:** Go only, latest stable release (go1.27.3 on 2026-11-08, pinned in `go.mod`). No cgo, no OpenSSL bindings. TLS via the standard library `crypto/tls`; the negotiated key-exchange group is read from `ConnectionState.CurveID`.
- **Reason:** Pure-Go `crypto/tls` can offer the hybrid post-quantum group X25519MLKEM768 and reports which group the server picked. That's what tells a PQ-ready endpoint from a vulnerable one. No cgo keeps the build to a single static toolchain with no native dependencies.

### Dependency vulnerability checking

- **Decision:** `govulncheck` is part of the workflow.
- **Reason:** Catch known vulnerabilities in the Go toolchain and dependencies of a security tool.

### Test targets (authorised scope)

- **Decision:** The probe is run only against:
  - Local TLS test servers on this machine (OpenSSL 3.5.6+ `s_server`, or nginx in Docker), with known configurations:
    - a) hybrid PQ: groups X25519MLKEM768 + x25519
    - b) classical only: groups x25519 / P-256
    - c) legacy: TLS 1.2 max, RSA-2048 certificate
  - The author's own domain: `altaieh.tech`
  - Nothing else.
- **Reason:** Only assets owned by, or explicitly authorised for, the author may be scanned. Local servers have known configurations, so the right answers are known in advance and the probe can be checked against them.

### Output

- **Decision:** JSON by default, plus a flag for a human-readable table in the terminal.
- **Reason:** JSON feeds the later inventory/classification steps; the table is for people reading results directly.

## 2026-11-08 — After step 1 review

### Name

- **Decision:** The tool is called **Hasr**. Go module `github.com/yaltayeh/hasr`, binary `hasr`.
- **Reason:** Author's choice.

### Repository and publication

- **Decision:** Public GitHub repository by Wednesday 2026-11-11. No LICENSE yet (undecided; do not add one). Before the first push: no private keys, certificates or credentials committed; test-lab certificates are generated at runtime and gitignored.
- **Reason:** The submission (deadline 2026-11-12) points to a public repo. Anything committed to a public repo stays in its history.

### Step order

- **Decision:** Step 2 = multi-handshake scan + classification. Step 3 = owner mapping file + Mosca priority + report organised by the SAMA circular's clauses. Cloud discovery after step 3, only if time remains.
- **Reason:** The SAMA mapping is what separates Hasr from generic TLS scanners, so the report comes before the cloud layer.

### Certificate chain verification

- **Decision:** Keep skipping verification during the handshake. Afterwards, verify the chain against the system roots and record the result as separate fields (verified true/false + error). A verification failure never fails the scan. *(Fields superseded on 2026-11-08 by "Certificate verification fields" below.)*
- **Reason:** The inventory must still see self-signed and private-CA certificates, but whether a certificate is publicly trusted is useful information in itself.

### Group names

- **Decision:** IANA TLS Supported Groups names (`x25519`, `secp256r1`, `X25519MLKEM768`) plus the numeric codepoint.
- **Reason:** Standard identifiers that don't depend on any one library.

### JSON output

- **Decision:** Not frozen; step 2 changes it. The new shape is proposed and approved before implementing. Per target: a list of probes (what was offered; result accepted / rejected / not_tested; what was negotiated) plus summary fields. Includes `schema_version`. Must stay mappable to CycloneDX CBOM later.
- **Reason:** One handshake can't show what a server supports. The shape has to record each attempt and its outcome.

### Step 2 probes

- **Decision:** Per target: default offer; hybrid only (X25519MLKEM768); classical only (x25519, secp256r1, secp384r1); MaxVersion TLS 1.2; TLS 1.1 only; TLS 1.0 only. Anything Go cannot test (finite-field DHE, SSLv3, groups Go doesn't implement, the handshake signature scheme) is recorded as `not_tested`, never as not supported.
- **Reason:** The inventory must never claim something it didn't check.

### Test lab server (c)

- **Decision:** Server (c) also accepts TLS 1.0 and 1.1 (`-cipher 'DEFAULT@SECLEVEL=0'`).
- **Reason:** Gives the scan a real legacy finding. OpenSSL 3+ refuses TLS 1.0/1.1 at its default security level.

### CI (later)

- **Decision:** In CI, govulncheck must be built with the project's toolchain: `golang/govulncheck-action` with `go-version-file: go.mod`.
- **Reason:** A govulncheck built with an older Go cannot load Go 1.27 code (seen in step 1).

## 2026-11-08 — Step 2 design

### Classification: two independent fields

- **Decision:** No single class. Two fields instead:
  - `key_exchange`: `hybrid` | `classical` | `unknown`, the harvest-now-decrypt-later axis. `hybrid` = any probe negotiated a hybrid group. `classical` = handshakes succeeded and none did. `unknown` = nothing accepted, or the evidence is inconclusive.
  - `legacy`: `true` | `false`, with reasons (TLS 1.0/1.1 accepted, weak suites accepted).
  - TLS 1.2 max with no 1.0/1.1 → `key_exchange` classical, `legacy` false, with the reason "no TLS 1.3: hybrid key exchange needs a protocol upgrade first". That reason stays; it will feed the crypto-agility rating later.
  - Table: two columns, KEX and LEGACY, instead of CLASS.
- **Reason:** The two lead to different actions. Disabling TLS 1.0/1.1 is a config change; enabling hybrid may need a library or protocol upgrade. A single "worst wins" class would hide that altaieh.tech already has hybrid.

### Probe results

- **Decision:** `accepted` | `rejected` | `error` | `not_tested`. `rejected` = the server sent a TLS alert. `error` = timeout, refused, reset, or closed without an alert. Timeout or reset is retried once before `error` is recorded. `error` never clears a rule and sets `complete` = false.
- **Reason:** An attempt that got no answer must never read as "not supported".

### Legacy probe offers

- **Decision:** `tls10_only` and `tls11_only` offer every cipher suite Go implements. A new probe, `tls12_weak`, is TLS 1.2 only and offers only RSA key transport, 3DES and RC4 suites. A negotiated weak suite goes into the legacy reasons. Before relying on it, a full handshake must be verified with an RSA key transport suite and with 3DES against a temporary `s_server`. If RC4 can't be verified, it is recorded as offered but unverified in the probe's detail field.
- **Reason:** With Go's default offer only, a server that speaks TLS 1.0 only with RSA key transport or 3DES would be marked rejected and look clean.

### Certificate verification fields

- **Decision:** Record each check separately, so one failure doesn't hide the others:
  - `chain_trusted`: system roots, using the certificates the server sent as intermediates;
  - `hostname_match`: checked when the target is a hostname; `not_checked` for IP targets;
  - `validity`: the certificate's dates.
- **Reason:** A self-signed, expired or wrong-name certificate are different findings with different fixes.

### JSON shape 0.2

- **Decision:** As proposed on 2026-11-08, with the changes above. Top level: `schema_version`, `tool`, `generated_at`, `targets`. Per target:
  - `probes`: `offered`, captured from the real ClientHello; `result`; `negotiated`;
  - `certificates`: deduplicated by SHA-256 fingerprint and referenced from probes;
  - `summary`.
- **Reason:** Records each attempt and its outcome, and stays mappable to CycloneDX CBOM (fingerprint → `bom-ref`, codepoints → cipher-suite identifiers).

### Repository content

- **Decision:** `BRIEF.md` stays out of the public repo: gitignored and kept locally. `DECISIONS.md` stays in the repo. Before the first push, the author reviews every line in it that mentions them personally.
- **Reason:** The brief holds personal background and working instructions, not project content.

## 2026-11-08 — After step 2 review

### Legacy: third value

- **Decision:** `legacy` can also be `unknown`: when there is no legacy finding and any of `tls10_only`, `tls11_only` or `tls12_weak` didn't give an answer. Shown as `?` in the table.
- **Reason:** A missing answer must not read as a clean result. "error never clears a rule" needs a value that says "not cleared".

### 3DES and RC4 verification

- **Decision:** Not verified before submission. Until then they stay "offered; not yet verified": per probe in the JSON, printed once under the table. Verify after submission with Docker, published on 127.0.0.1 only.
- **Rule:** Never run a test server on all interfaces.
- **Reason:** Deadline. Every way to verify them now either exposes a weak-cipher server on the LAN or costs time needed for step 3.

### DECISIONS.md wording

- **Decision:** Refer to the person as "the author". Corrections say what was wrong and what fixed it, not who found it. No details of the development machine.
- **Reason:** The file is published.

## 2026-11-08 — Step 3 inputs

### Regulatory source text

- **Decision:** The report is organised by SAMA Circular No. 482021280, dated 1448/03/14 H (27 August 2026), signed by the Deputy Governor for Supervision. The circular numbers its clauses First to Fourth; the report calls them Clause 1–4. Clause 2's two bullets are labelled 2a and 2b; that labelling is ours.
- **Decision (superseded later the same day, see "Step 3 answers"):** ~~Use the author's English translation, labelled "unofficial translation".~~
- **Decision:** The official Arabic PDF is kept in `refs/`, which is gitignored and must never be committed.
- **Reason:** The report must cite the regulation exactly. The official PDF is not the author's to publish.

### Clause 2 is about the procedure's completeness

- **Decision:** Clause 2 asks for the *accuracy and completeness of the procedures*, not only an inventory. The report's Clause 2 section therefore carries, as evidence:
  - the completeness figure;
  - the not-tested section;
  - the not-assessed section;
  - the needs-owner-input section.
- **Reason:** Those are what show the inventory procedure is complete and accurate.

### Clause 2 sections

- **Decision:** Under Clause 2, as evidence of completeness:
  - **Completeness figure.**
  - **Needs owner input:** scanned, but not in the mapping file. Findings shown, priority `unknown`.
  - **Mapped but not scanned:** in the mapping file, but not scanned.
  - **Not assessed:** unreachable or incomplete, listed with the error. Never given a low priority.
  - **Not tested:** the scanner's stated limits:
    - SSLv3;
    - finite-field DHE;
    - groups no probe offers;
    - the handshake signature scheme;
    - 3DES and RC4, which are offered but not yet verified.
- **Reason:** Clause 2 asks for complete and accurate procedures. Gaps and limits are part of that evidence, not footnotes.

### What each clause section says

- **Decision:** Every clause section states plainly what Hasr provides and what the institution still has to do itself. Each section shows the clause's due date:
  - Clause 1: end of Q1 2027.
  - Clause 2: end of Q4 2026.
  - Clauses 3 and 4: no date in the circular.
- **Decision:** Clause 3 carries the recommended actions per finding (in step 3 scope). Clause 4 states that scans are repeatable and that change tracking is planned (change tracking itself is not in step 3).
- **Reason:** The tool covers only part of Clauses 1, 3 and 4. The report must not suggest it covers the rest.

## 2026-11-08 — Step 3 answers

### Clause text

- **Decision (superseded later the same day, see "Policy values"):** ~~Until the official English text is provided, sections are labelled "Clause 1–4 (summary)" and nothing is quoted.~~
- **Decision:** The official English text is not available yet. The report quotes the author's English translation verbatim, labelled "unofficial translation"; the official text is the Arabic circular.
- **Open:** the nine differences found between the translation and the Arabic PDF are awaiting the author's decision. The translation is quoted unchanged until then.

### Mapping file

- **Decision:** CSV, no third-party dependency. Entries match scan targets on exact `host:port`.
- **Decision:** Columns:
  - `target`
  - `system`
  - `service`
  - `owner`
  - `data_classification`
  - `data_shelf_life_years` (X)
  - `migration_years` (Y)
  - `third_party`
  - `constraints`
- **Decision:** Classification labels default to the Saudi NDMO four levels (Top Secret, Secret, Restricted, Public), and they are configurable.
- **Reason:** Spreadsheet-friendly, matching how institutions inventory today; no dependencies.

### Mosca: X, Y, Z

- **Decision:** X comes from a default per classification level, overridable per entry. The values will be given by the author.
- **Decision:** Y comes from a default derived from the scan, overridable per entry. The scan categories are: already hybrid / TLS 1.3 classical / no TLS 1.3. The values will be given by the author.
- **Decision:** If `third_party` is not in-house and Y is empty, Y is unknown, so priority is unknown. A vendor's timeline is never guessed.
- **Decision:** Z is one global value, with its source printed in the report. The source can be a threat estimate or a regulatory date. The value will be given by the author. Scenarios come later.
- **Reason:** X belongs to the data, Y to the system, Z to the threat; each comes from the people who know it.

### What Mosca applies to

- **Decision:** A hybrid target that also accepts classical key exchange is "mitigated for PQ-capable clients": lower priority, not at risk. It carries a note that residual risk depends on client support.
- **Decision:** Certificates are listed with their algorithms; no Mosca priority in step 3.
- **Reason:** Harvest-now-decrypt-later concerns key exchange; authentication can't be broken retroactively.

### Priority

- **Decision:** No named levels yet. Each asset gets at risk yes/no plus the margin (X + Y − Z), sorted by margin.

### Report

- **Decision:** A single self-contained HTML report, with the JSON written alongside. Markdown later.
- **Decision:** Two commands:
  - `hasr scan` writes JSON. It takes targets from the command line and/or `--targets mapping.csv`.
  - `hasr report` reads the scan JSON and the mapping CSV.
- **Decision:** A recommended action for each finding is in step 3. The crypto-agility rating and change tracking wait until after submission.
- **Reason:** Re-reporting without re-scanning, and the scan JSON is kept as evidence.

## 2026-11-08 — Policy values

### Where the values live

- **Decision:** All values are in `policy/default.json`, committed to the repo; no numbers are built into the code. `hasr report` reads it by default (`--policy` overrides).
- **Decision:** Every value carries its source text, and the report prints the source next to the value.
- **Reason:** Reviewable, citable values; a reader can see where each number comes from.

### Z

- **Decision:** Z is the calendar date 2030-12-31, converted to years on each run.
- **Source text:** "NIST IR 8547 (final, 27 October 2026) deprecates all quantum-vulnerable public-key algorithms after 2030. The EU Coordinated Implementation Roadmap (June 2025) sets the end of 2030 for high-risk use cases, including finance. SAMA Circular 482021280 sets no migration date."
- **Links:** https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf and https://www.enisa.europa.eu/media/56885
- **Verified by the author:**
  - against the final NIST IR 8547 PDF (October 2026). Sections 4.1.1 and 4.1.2 deprecate all quantum-vulnerable digital signature and key-establishment algorithms after 2030 and disallow them after 2035, at all approved strengths;
  - against the ENISA presentation of the EU roadmap, which names finance among the critical infrastructure due by end of 2030.

### X (data shelf life)

- **Decision:**
  - Public: 0 years. Source: "No confidentiality requirement."
  - Restricted, Secret, Top Secret: 10 years. Source: "Minimum record-keeping period under Article 12 of the Saudi Anti-Money Laundering Law (SAMA Rulebook, record keeping): at least ten years from the end of the relationship or transaction. A floor, not a ceiling; override per entry."

### Y (migration time)

- **Decision:**
  - Already hybrid: 0 years. Source: "Hasr assumption: hybrid key exchange is already in place, so key exchange needs no migration. Certificates are listed separately; client support is not measured by Hasr and remains for the institution to track."
  - TLS 1.3 with classical key exchange: 1 year. Source: "Hasr assumption: a configuration change or library upgrade within one change cycle."
  - No TLS 1.3: 3 years. Source: "Hasr assumption: a protocol or platform upgrade."
- **Decision:** The report marks both of the assumption values (1 and 3 years) "assumption; override per entry".

### Implementation details approved 2026-11-08 (formerly provisional 17–20)

- Policy file format:
    - every value is `{years, source, assumption}`;
    - Z is `{date, source}`;
    - unknown fields, a value without a source, and negative numbers are errors.
- The Z conversion: (date − report date) in days ÷ 365.25, rounded to 0.01 years (4.15 on 2026-11-08). The margin is rounded the same way.
- The source text for "already hybrid: 0" started as a draft by Claude; the author approved it and added a sentence (see Y above).
- The values table sits in Clause 2a, right under the priority table, rather than in the appendix.

## 2026-11-08 — Report refinements

### Margin of mitigated assets

- **Decision:** For targets marked "Mitigated for PQ-capable clients", the margin says it applies only to clients without ML-KEM support, e.g. "+5.85 (clients without ML-KEM only)".
- **Reason:** A reader shouldn't wonder why a mitigated asset has a positive margin.

### Translation review

- **Decision:** The nine differences between the author's translation and the Arabic PDF are written out in full for review, each with the author's text, the Arabic, the proposed change and the reason (`refs/translation-review.md`). The author's text stays in the report until the author decides on each one.
- **Outcome:** all nine accepted.
  - 1, 2, 3, 8, 9: the proposed wording is applied. For 8: "comprehensiveness" and "taking into account, at a minimum, the following:".
  - 4, 5, 6: the subject line, preamble and closing are added to `refs/sama-482021280-unofficial-translation.txt`. The report prints:
    - the subject line, as the circular's title;
    - the sentence "Accordingly, financial institutions are required to take the following actions:", before the clauses;
    - the distribution list (difference 1), labelled "Distribution".

    It does not print the rest of the preamble or the closing.
  - 7: the 2a/2b labels stay, with the note that they are Hasr's.
- **Reason:** Fidelity to the Arabic original.

## 2026-11-08 — Repository, privacy review and README

### Ignore rules

- **Decision:** `.gitignore` keeps `/BRIEF.md` and `/refs/`.
- **Reason:** The protection travels with the repository; the names alone reveal nothing.

### History

- **Decision:** The initial commit is not amended; later changes go in new commits.
- **Reason:** Nothing in it needed removing: the ignore entries reveal nothing.

### Git identity

- **Decision:** The author's name and email are set in this repository's git config only. The global git config is not changed, and the email is the author's GitHub noreply address.
- **Reason:** Keeps a personal email address out of the public history.

### Commit attribution and time

- **Decision:** Commit messages end with the `Co-Authored-By` line for Claude; no session link. Commit times stay in local time.
- **Reason:**
  - `Co-Authored-By` states openly that development is AI-assisted; the decisions themselves are recorded in this file.
  - The session link is dropped because it is private and no reader can open it.
  - Local time is kept because the author's location is already public in the project.

### Branch

- **Decision:** The default branch is `main`.
- **Reason:** It matches GitHub's default for new repositories.

### Privacy review before the first push

- **Checked:** every file to be committed, and the commit message, for:
  - the author's name and username;
  - the author's domain;
  - email addresses;
  - absolute paths;
  - details of the development machine (operating system, CPU architecture, package manager, local tool versions, service state);
  - attribution lines.
- **Rule:** Committed files carry no details of the development machine. The "DECISIONS.md wording" rule applies to every committed file, not only this one. The author's GitHub username and own domain may appear where the project needs them: the module path, and the author's own scan target.

### README

- **Decision:** `README.md`, approved by the author:
  - the name comes from «حصر», the word Clause 2 uses for inventory;
  - what Hasr does, and which clause of the circular each part serves, claiming only what is built;
  - how it works, briefly, with detail left to this file;
  - quick start with the test lab, both commands, and the sample mapping and policy files. The sample scan's exit status 1 is marked as expected;
  - responsible use;
  - limitations;
  - status and roadmap: cloud discovery next, the rest under "Planned";
  - the license line "No license yet; all rights reserved."

  It does not mention the project brief, the local reference folder or the development machine. Examples use the test lab only.
- **Decision:** `docs/report.png` shows two areas of one lab-only report: the header with its overview cards, and the Clause 2a priority table. A dashed line joins them, and the caption says they are two parts.
- **Reason:** A public reader sees what Hasr does today, without overclaiming.

### Definition of Z

- **Decision:** Z is "the time until the quantum threat or a regulatory deadline". It is worded the same in the README and in the report's Clause 2a note and values table.
- **Reason:** The default Z is a deadline (31 December 2030), not an estimate of when a quantum computer will exist.

## 2026-11-09 — Cloud discovery (AWS)

### Architecture

- **Decision:** Cloud discovery is split into three stages, with a provider-neutral format between them and the core:
  1. a collector: `collectors/aws/collect.sh`, a POSIX `sh` script that runs only read-only `aws` CLI commands and writes their raw JSON to a folder;
  2. a converter: `hasr cloud aws --from RAW_DIR`, written in Go in `internal/cloud/aws`, turns that folder into the neutral format on stdout;
  3. `hasr report --cloud FILE` reads only the neutral format. The flag may be repeated, one file per provider.
- **Reason:**
  - Hasr itself never touches AWS credentials and keeps zero third-party dependencies.
  - The raw folder is evidence the institution can keep.
  - Other providers (Google Cloud, Azure, Cloudflare) can be added later without changing the core.
- **Decision:** Provider-specific rules live in the provider's package. Each verdict carries its basis and a source link. Examples are "PQ in the policy name" and the translation of OpenSSL-style cipher names. The report sees only verdicts.
- **Decision:** Minimal layout: `internal/cloud` (neutral types, reader, validation) and `internal/cloud/aws`. The rest stays in `package main`, with no refactor.
- **Decision:** The neutral format uses the scan's own vocabulary (`key_exchange`, `legacy`, version strings, certificate refs), so the report can compare field by field. It stays mappable to CycloneDX CBOM.

### Scope

- **Decision:** Load balancers (ELBv2) and their listeners, SSL policy contents, listener certificates, ACM certificate details, and tags. CloudFront, API Gateway, KMS and Classic Load Balancers go under "Planned".
- **Decision:** From the API, "hybrid" means the policy name contains `PQ`. This is AWS's documented rule ("Security policies with PQ in their names offer hybrid post-quantum key exchange"), and the report shows the AWS link with it.
  - **Reason:** `DescribeSSLPolicies` returns protocols and ciphers but no key-exchange groups.
- **Decision:** Tags may fill empty `owner`, `system` and `service` fields only, never `data_classification`. The CSV wins on conflict, and the report shows each value's source.
- **Decision:** Hasr never scans an endpoint because the API found it. Discovered endpoints are listed, and they count against the completeness figure under Clause 2.

### Joining the scan and the cloud data

- **Decision:** A cloud record matches a `host:port` target when:
  - the target's host is one of the record's hostnames, or the target's CNAME chain ends at one; and
  - the port is the listener's port.
  An explicit override column comes later, if time allows. The certificate is a cross-check only.
- **Decision:** When the scan and the matched records disagree, the worst of all of them counts, consistent with "error never clears a rule". Every disagreement is listed under Clause 2 (accuracy).
- **Decision:** A new policy value `migration_years_default.managed_tls_policy` = 0.5 years. Source: "Hasr assumption: a policy switch on a managed TLS endpoint, plus client-compatibility testing."
- **Decision:** Clause 2b lists "the TLS policy can be changed in place" as crypto-agility evidence.
- **Decision:** When a matched cloud record shows that the TLS policy is a managed setting and that it lacks hybrid key exchange, the record's recommendation replaces the action of the scan's key-exchange finding. The scan's finding text, its evidence, stays. The finding then also notes what the single switch changes. Without a cloud match, the scan's wording stays.
  - For AWS the action is "Switch the listener to a PQ security policy (AWS recommends `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`); test client compatibility first", with the AWS documentation link.
  - The note is worked out from the two policies' contents as read (`describe-ssl-policies`). For `2016-08`: adds hybrid post-quantum key exchange, adds TLS 1.3, removes TLS 1.0 and 1.1, removes RSA key transport suites.
  - The record's own key-exchange finding is then not repeated.
  - The AWS wording, the recommended policy and the effects come from the AWS converter, in the neutral format's `recommendation` field. The report only applies them.
  - **Reason:** For a managed load balancer, "enable TLS 1.3 first (protocol upgrade)" is wrong. One setting does it.

### Credentials and safety

- **Decision:** The collector runs as the IAM role `hasr-readonly`, with only the permissions in the committed `collectors/aws/iam-policy.json`:
  - `elasticloadbalancing:Describe*` (five actions, listed in the file);
  - `acm:ListCertificates`, `DescribeCertificate`, `ListTagsForCertificate` and `GetCertificate`. `GetCertificate` returns the public certificate only.
  The role is assumed from the project's admin role through an AWS profile (`role_arn` and `source_profile`).
- **Reason:** IAM enforces read-only as a second guard. The first guard is a test that fails if the collector script runs anything other than `describe-*`, `list-*` or `get-*`.
- **Decision:** The collector refuses to run with root credentials. It records every command and its exit status in `manifest.json`, and failed regions become stated limits under Clause 2. `--region` is required and may be repeated.
- **Decision:** Raw collector folders, converted files, Terraform state, plans and variables are gitignored. The account ID stays in local output only.

### Demo infrastructure

- **Decision:** `cloudlab/aws/`, Terraform. State stays local on the machine of whoever runs the demo. Every change in AWS goes through Terraform; the author runs `apply` and `destroy` after reading the plan.
- **Reason:** The author knows Terraform. It is a demo only, so remote state isn't needed.
- **Decision:**
  - Two internet-facing Application Load Balancers with fixed responses:
    - `pq` uses `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`;
    - `default` sets no policy, so it gets `ELBSecurityPolicy-2016-08`, the default for Terraform, the CLI and CloudFormation (the console's default is the PQ policy).
  - Port 443 is open to the scanning machine's /32 only.
  - The demo has its own VPC.
  - No plaintext listener.
  - Disagreements are shown in tests only.
- **Reason:** PQ and non-PQ policies cannot share one load balancer.
- **Decision:** The certificate is self-signed RSA 2048, generated by an ephemeral `tls_private_key`. It is passed only to write-only arguments: `private_key_pem_wo` (TLS provider 4.4.2) and `private_key_wo` (AWS provider 6.72.0, available since 6.47.0). The key never enters the plan or state files. Terraform 1.11 or later, exact provider pins, and the lock file is committed.
- **Decision:** Terraform also creates the role `hasr-readonly`. Only the project's admin role in the same account may assume it, and `destroy` removes it.
- **Decision:** The demo region is `eu-north-1` (Stockholm).
- **Reason:** The demo account belongs to AWS's new account experience: a project inside an AWS-managed organization, with spend limits. Its AWS-managed service control policy denies every action outside the project's own Region, which is `eu-north-1`.
  - A first plan in `us-east-1` was refused with an explicit deny from that policy.
  - Bahrain (`me-south-1`) and the UAE (`me-central-1`) were not options: the author reports that Bahrain is unavailable after this year's damage and that the UAE region lost an Availability Zone.
  - No advanced features or project settings are changed.
- **Decision:** The demo's endpoints (the load balancers' DNS names) may be scanned only while the Terraform state lists them. After `destroy` their addresses return to AWS.
- **Decision:** After `destroy`, a script run as the admin checks that nothing is left:
  1. the state is empty;
  2. no resource carries the tag `Project=hasr-demo`;
  3. direct listings of load balancers, certificates, VPC resources and the role come back empty;
  4. `hasr cloud aws` finds no load balancers.
  The author checks billing the next day.
- **Decision:** `cloudlab/aws/up.sh` plans the demo with the current public IP. It reads the IP from `https://checkip.amazonaws.com` and accepts only four decimal octets, each 0–255. It passes the IP as `TF_VAR_my_ip` (a /32), in the environment and not on the command line. It writes the full plan output to the gitignored `run/plan.log` and shows only summary lines with IPv4 addresses redacted, then stops for the author to apply. It refuses to run while `terraform.tfvars` sets the IP, because a tfvars value overrides `TF_VAR_*`.
- **Reason:** The author's public IP changes; the security group then drops the scan's connection attempts silently.
- **Decision:** `cloudlab/aws/scan-demo.sh` scans the two load balancers only while the Terraform state lists them. It writes a runtime mapping (with the DNS names) and the scan to the gitignored `cloudlab/aws/run/`.
- **Decision:** The AWS MCP server is not used in this project and stays disabled.
- **Reason:** Its endpoint is in `us-east-1`, which the demo account's service control policy denies, and nothing in Hasr needs it. The collector uses the AWS CLI directly.
- **Correction (same day):** `hasr-readonly` was first planned as an IAM user, on the assumption that Terraform would run as root, and root cannot call `sts:AssumeRole`. The admin identity is in fact the project's role `AccountFullAccessRole`, which can assume roles, so `hasr-readonly` is a role again. The user, its console-password step and its sign-in policy were removed.

### Probe stages: no TCP connection vs a TLS-level close

- **Decision:** Each probe connects in two stages:
  1. a TCP connection;
  2. the TLS handshake on it.
  An `error` result records its `stage` (`tcp` or `tls`), and the two are worded differently:
  - "no TCP connection: no answer to the connection attempt (timeout)" means silence: every SYN unanswered;
  - "no TCP connection: …" with the system's reason covers refused or unreachable;
  - "TCP connected, then the server closed the connection during the TLS handshake without an alert (EOF)".
  When every probe of a target fails at the TCP stage, the report says "unreachable: no TCP connection (…); nothing about its TLS is known". The scan schema stays 0.4: the field was added before 0.4 was published.
- **Reason:** Silence at the TCP level (for example, a security group dropping packets) says nothing about TLS. It must never be confused with a server that refuses a TLS offer by closing the connection.

### How a server refuses: close_notify and zero-byte closes

- **Observed:** on the live demo, two probes ended in `EOF`. They were `hybrid_only` (TLS 1.3 only) against the load balancer with `ELBSecurityPolicy-2016-08`, and `tls12_weak` against the one with the PQ policy.
  - The author checked the first with `openssl s_client -tls1_3 -msg` and `tcpdump`. After ACKing both segments of the ClientHello (1392 + 123 bytes), the load balancer sent one 7-byte record, `15 03 03 00 02 01 00`: an alert record, level warning (1), description close_notify (0). It sent the FIN in the same instant; the two arrived reordered, and SACK recovered them.
  - So the load balancer does not close silently. It answers with close_notify and gives no reason.
- **Expected by the standards:**
  - RFC 8446, section 4.2.1: a server that supports none of the offered versions aborts with a `protocol_version` alert.
  - A TLS 1.2 server with no cipher suite in common sends `handshake_failure` (RFC 5246, section 7.4.1.3).
  - close_notify (RFC 8446, section 6.1) is meant for ending a connection, not for refusing a handshake.
- **Why Hasr saw EOF:** Go's `crypto/tls` returns `io.EOF` both for a received close_notify and for a bare FIN with no bytes. Only an alert with an error description becomes a "remote error".
- **Decision:** The raw TCP connection given to `tls.Client` is wrapped in a recorder, standard library only, that keeps the first 16 bytes the server sends and counts them all. When a handshake ends in `EOF`:
  - **close_notify first:** the first record is an alert carrying close_notify, so no ServerHello came before it. The result is `rejected`, with "closed with close_notify, no reason given".
  - **zero bytes, then FIN:** retried once. If the retry gives the same, the result is `closed`. `closed` counts as a refusal only if another probe on the same target was accepted. Otherwise it becomes `error`, with "not counted as a refusal: no probe on this target was accepted".
  - **Unchanged:** an alert with a reason is still `rejected`. A reset or timeout is still `error`, and so is any other EOF.
  - **Evidence:** the probe JSON records `bytes_before_close` (`hex` of at most 16 bytes, and `count`) whenever a handshake ended in EOF.
- **Reason:** A close_notify is an answer from the server, and a scanner that calls it "no answer" misreports. A bare FIN is weaker evidence, because a middlebox can also drop connections. That's why it needs a matching retry and a sign that the target answers other offers.
- **Observed inconsistency (AWS ALB):** the load balancer refuses in two different ways.
  - **Below the policy's minimum version** (TLS 1.0 or 1.1 against the PQ policy): a proper fatal `protocol_version` alert.
  - **Above the policy's maximum version** (TLS 1.3 only against `2016-08`), **or with no cipher suite in common** (weak suites only against the PQ policy): close_notify, with no reason.
- **Supersedes:** options (a)–(c) proposed on the same day for the "silent close". The close was not silent.
- **Tests:** fake servers on 127.0.0.1 that:
  - send close_notify, then close;
  - close with zero bytes once (the retry is accepted);
  - close with zero bytes every time (`error`, never a refusal);
  - send a fatal `protocol_version` alert.
  A unit test checks that `closed` counts as conclusive when another probe was accepted.

## 2026-11-10 — Target form

### One canonical form for every target

- **Decision:** Every target is normalised to one form before anything else: command-line targets, `--targets`, the mapping CSV, and the targets of a scan JSON when the report reads it. Matching stays on exact `host:port`, now of the canonical form. The form is:
  - the port is decimal digits only, 1–65535, written without leading zeros. An empty port (`host:`) and service names (`host:https`) are rejected with an error;
  - the host is lowercased with one trailing dot removed;
  - IP addresses are written in their standard form, with IPv6 in brackets (`[2001:db8::1]:443`).
- **Decision:** A target without a port defaults to `:443` on the command line only. The mapping CSV still needs an explicit port.
- **Decision:** An invalid command-line target stops `hasr scan` with exit status 2 before anything is sent. Before this, it was scanned as an invalid target and recorded with an error. Two CSV rows that differ only in form are duplicates.
- **Decision:** URLs (`https://…`) and hosts with characters other than letters, digits, `-`, `.` and `_` are rejected. Internationalised names must be given in their `xn--` form.
- **Reason:** `net.SplitHostPort` does not validate the port, and the CSV is matched to scan targets on exact `host:port`. Without one form, `bank.sa:443` on the command line and `BANK.SA.:443` in the CSV would not match.
- **Unchanged:** The probe dials the full `host:port`. SNI carries the host alone, and none is sent for an IP address (including IPv6 with a zone).

## Corrections

- **2026-11-08:** The step 1 summary said Go's client "won't go below TLS 1.2". That was wrong. TLS 1.2 is only Go's *default* minimum; setting `MinVersion`/`MaxVersion` explicitly enables TLS 1.0/1.1. Fixed by giving the TLS 1.0 and TLS 1.1 probes explicit versions. Verified on go1.27.3 against test server (c): TLS 1.1 and TLS 1.0 handshakes both succeed.

## Verification log

- **2026-11-08, RSA key transport:** verified. `tls12_weak` completed full handshakes with `TLS_RSA_WITH_AES_128_GCM_SHA256` and `TLS_RSA_WITH_AES_128_CBC_SHA` against temporary OpenSSL `s_server`s on 127.0.0.1:8446 (TLS 1.2, one suite each). The `default` probe was rejected by both, which confirms why the probe is needed.
- **2026-11-09, AWS demo (eu-north-1), live run:**
  - **Collector:** ran as `hasr-readonly`: 13 calls, 0 failed. The Terraform state held no private key (0 matches for `PRIVATE KEY`).
  - **Scan, PQ policy:** hybrid, X25519MLKEM768 by default; classical is still accepted on TLS 1.3 (x25519) and TLS 1.2. TLS 1.0 and 1.1 are rejected with `protocol_version`. The weak-suite offer is rejected with close_notify.
  - **Scan, policy `2016-08`:** TLS 1.0, 1.1 and 1.2, with RSA key transport (`TLS_RSA_WITH_AES_128_GCM_SHA256`). The TLS 1.3-only hybrid offer is rejected with close_notify.
  - **Scan vs API:** the scan and the API agree on every field compared, including the certificate (same SHA-256 as the ACM certificate on the listener). No disagreements.
- **2026-11-09, AWS demo destroyed, leftover check (`check-clean.sh`):** 12 of 13 checks passed: an empty state, and direct listings of load balancers, ACM certificates, VPC, subnets, security groups, security-group rules, internet gateways, route tables, the load balancers' network interfaces and the IAM role, plus `hasr cloud aws` with 0 endpoints. The tag search still listed one `ec2` `security-group-rule`, although EC2 itself returns no such rule and its security group is gone. That is the tagging index lagging behind the deletion, which the script already warned about. A direct check for security-group rules was added to the script after this run. Still to do: re-run the tag search later, and the author checks billing the next day.
- **2026-11-08, 3DES and RC4:** NOT verified. The available OpenSSL builds have no 3DES or RC4 suites. The one local library that has both cannot listen on 127.0.0.1 only, so it wasn't run. For now, the probes that offer these suites (`tls10_only`, `tls11_only`, `tls12_weak`) say "offered; not yet verified" in their detail field. The decided rule for RC4 is applied to 3DES too, pending a decision.

## Provisional — NOT yet decided (awaiting confirmation)

Needed to build and run steps 1–3. Each one stays provisional until confirmed or changed.

1. Layout: `package main` at the repo root, split by concern. Scan: `main.go`, `probes.go`, `certs.go`, `summary.go`, `output.go`, `names.go`. Report: `report_cmd.go`, `mapping.go`, `policy.go`, `assess.go`, `html.go`. Plus `*_test.go`; test lab in `testlab/`.
2. Leaf certificate only in the output (intermediates are used for verification but not recorded). Explicit `host:port` required (no default port). Timeout 5s per handshake attempt. Exit codes: 0 ok, 1 some target had no accepted probe (or was invalid), 2 usage/output error.
2a. JSON additions beyond the approved shape: `tool.go`, probe `attempts`, summary `inconclusive_probes`, certificate `chain_error` / `hostname_error`.
2b. When a leaf is expired or not yet valid, chain trust is evaluated at a moment inside its validity window, so expiry shows under `validity` only.
2c. In JSON, `legacy` is a string, `yes` | `no` | `unknown` (it was a boolean). `schema_version` went to 0.3 because the field's type changed.
2d. A Go-side handshake failure without a server alert (e.g. the server picks a version we didn't offer) is recorded as `error`, not `rejected`.
3. Test lab: OpenSSL `s_server` (3.5.6 or later), not Docker. Ports 127.0.0.1:8443/8444/8445. Self-signed certs: ECDSA P-256 for (a) and (b), RSA-2048 for (c), all SHA-256. Target (b) is one server offering both x25519 and P-256.
4. Go 1.27.3 comes from the `go.mod` pin plus Go's built-in toolchain download; no system-wide Go installation is changed.
5. govulncheck v1.9.0 runs locally, built with go1.27.3, until CI exists.
6. `.gitignore` also ignores the `hasr` binary and any `*.key`, `*.pem`, `*.crt`, `*.p12`, `*.pfx`, `.env` anywhere in the tree.
7. `hasr scan` takes flags before targets; the old bare `hasr host:port` form is gone.
8. *(Superseded by "Policy values"; kept for history.)* Policy (X, Y, Z and classification labels):
   - a JSON file passed with `--policy`;
   - without one, built-in defaults: the NDMO labels and no X, Y or Z values;
   - Z is in years from the report date.
9. The scan-derived default Y applies only when `third_party` says `in-house` (any letter case). An empty `third_party` counts as not stated, so Y is unknown.
10. Mapping CSV:
    - columns are matched by name, in any order;
    - errors: unknown, missing or repeated columns; duplicate targets; labels outside the list; negative or non-numeric years;
    - a spreadsheet byte-order mark is accepted, and years may be decimals.
11. Priority:
    - order: at risk (largest margin first), then unknown, then not at risk, then mitigated;
    - "at risk" means margin > 0 (strict, as in X + Y > Z);
    - a hybrid target that accepts no classical key exchange is "not at risk".
12. Sections:
    - an unmapped target goes to "needs owner input" even if it is also unreachable;
    - a mapped target with `complete` = false goes to "not assessed", even if it has partial findings;
    - Clause 3 also lists the findings of targets that need owner input, under their own heading.
13. Wording of findings and recommended actions (`assess.go`, `findings`). This includes a "quantum-vulnerable signature" finding for every RSA, ECDSA or Ed25519 certificate, and certificate trust, hostname and validity findings.
14. Report output:
    - `hasr report` writes `hasr-report.html` and `hasr-report.json` by default (`--html`, `--json`);
    - the report JSON has `kind: hasr-report` and `schema_version` 0.1.
15. The clause titles and the "What Hasr provides / What the institution still has to do" texts (`html.go`, `clauses`) are drafts in Hasr's own words. The clause text itself is the author's translation, verbatim.
16. `testlab/mapping.csv` holds fictional sample rows marked "(sample)". `altaieh.tech` is left unmapped on purpose, so it shows under "needs owner input".
21. Source links:
    - live in a `links` list next to each source (`z.links`, or `links` on any value);
    - only absolute https URLs are accepted;
    - the report shows them as plain links, which is the only kind of external reference the page has.
22. The report JSON carries `mosca.margin_scope` ("clients without ML-KEM only"). It is set on mitigated assets that have a margin.
