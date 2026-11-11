# DNSSEC infrastructure measurement study

This repository contains the source code, case profiles, zone sources and selected derived results for a Master's thesis on how DNS infrastructure processes DNSSEC-related queries. The study compares the query sent by a client, the question visible at a controlled authoritative server and the final client response.

The two phases use different environments. The laboratory tests known resolver deployments under controlled configurations. The public phase measures externally operated DNS service addresses while recording traffic at a university-operated NSD server. The public addresses are endpoints, not verified identities of independent recursive systems.

## Repository layout

| Directory | Contents |
| --- | --- |
| `lab/cmd/` | Laboratory measurement client and custom authoritative server |
| `lab/config/` | One 120-case main profile and separate CDS/CDNSKEY and TKEY profiles |
| `lab/scripts/` | Analysis code that produces the published laboratory comparison files |
| `lab/zones/` | Unsigned laboratory zone sources |
| `lab/results/` | Derived event-level comparison and aggregated 120-case overview |
| `public/cmd/` | Candidate screening and 23-case measurement programs |
| `public/config/` | Frozen public measurement case profile |
| `public/zones/` | Public test-zone sources and an NSD zone configuration example |
| `public/results/` | Saved aggregate audit of the four public main runs |

## Requirements

- Go 1.26.4 for both independent Go modules. Dependencies are pinned in each phase's `go.mod` and `go.sum`.
- Python 3 for the laboratory comparison script. It uses the standard library.
- For a new laboratory measurement: BIND 9.20.11, Unbound 1.22.0, PowerDNS Recursor 5.2.4, the BIND DNSSEC tools, `dig`, `systemctl` and a controlled authoritative environment. The final laboratory VM ran Ubuntu 25.10.
- For a new public measurement: a domain and authoritative server under the researcher's control, an address list and NSD with packet capture configured separately.

From the repository root, check the current Go source without sending DNS queries:

```sh
(cd lab && go test ./...)
(cd public && go test ./...)
```

These checks compile the supplied source. They do not verify the historical executables or the original deployment state.

The public entry points can also be opened without sending DNS traffic:

```sh
(cd public && go run ./cmd/screening -h && go run ./cmd/measurement -h)
```

The public commands display their available parameters. Running a measurement requires the external address list and controlled DNS environment described below.

## Laboratory phase

The main catalog contains 120 cases. Five repetitions across six resolver and validation-mode conditions produced 3,600 client events. The CDS/CDNSKEY and TKEY controls were supplementary and are not included in that denominator. Each profile in `lab/config/` was used in both modes. Validation was configured on the resolver, not in the client profile. The laboratory client is `lab/cmd/measurement/main.go`, and the custom authority is `lab/cmd/authoritative/server.go`.

The two files in `lab/results/` are unchanged copies of the final derived comparison. They are not raw DNS messages or original event logs:

| File | Contents | Thesis connection |
| --- | --- | --- |
| `lab/results/main_processed_events.csv` | One processed comparison row per main client event, including associated authoritative observations within the bounded logging window | Source-level detail for the 3,600-event laboratory results in Chapter 6 |
| `lab/results/main_case_overview.csv` | One summary row for each of the 120 main cases across the six resolver-mode conditions | Case inventory and laboratory contrasts in Chapter 6 and the appendix |

The event-level file can be filtered and counted to inspect the laboratory comparison. `lab/scripts/compare_results.py` produces both published CSVs from the original client and authoritative event logs. Those raw logs are stored separately and are not included in this repository.

The supplied laboratory profiles can be checked without sending DNS queries. From `lab/`, run:

```sh
go run ./cmd/measurement --validate config/main.json
```

A new laboratory run requires signed zones, resolver services and local configuration before running the supplied Go programs. Use a distinct `--run-id` for each resolver mode so a second run does not overwrite the first. Private zone-signing keys, complete active resolver configurations and the exact signed zone bytes loaded during the historical runs are not included.

## Public-resolver phase

The screening program in `public/cmd/screening/` evaluated directory candidates using a controlled negative-name question. It reads only `all.txt`, removes duplicate IP addresses while preserving file order and assigns sequential resolver IDs. The main program in `public/cmd/measurement/` used the 23-case profile in `public/config/measurement_cases.json`. The four main cohorts together covered 6,232 selected IPv4 addresses, with one main attempt per address and case. Supplementary TKEY checks remain separate from those totals.

The `public/results/main_aggregated_results.json` file contains aggregate results from the four main runs. The `runs` entries summarize capture checks, `client_groups` reports client outcome counts for all 23 cases, `case_first` describes first matching authoritative questions for the 12 unique-name cases, and `tcp_audit` and `tkey_client` hold separate transport and TKEY summaries. It contains no resolver IP list or packet payloads. The 11 fixed-name cases do not support an address-by-address authoritative match. The JSON supports inspection of the public results in Chapter 6, including the distinction between client outcomes and NSD observations. It does not contain every derived comparison in the thesis, including the strict non-truncated TXT-bearing final-response counts.

The raw public measurements, address lists, packet captures and full audit code are retained separately. The published JSON supports inspection and recalculation of its aggregate counts. Packet matching, capture checks and the full thesis analysis require the separately retained evidence.

For a new public experiment, sign and deploy the supplied zone sources using private keys kept outside the repository, configure NSD and establish the delegation. From `public/`, provide a candidate directory containing `all.txt` to the screening program. The measurement program takes a separate selected-address CSV with the columns `resolver_id`, `ip`, `address_family`, `authoritative_observed` and `provider_dnssec_label`. The last two columns contain `true` or `false`. Both programs default to a dry run:

```sh
go run ./cmd/screening -input /path/to/candidates -only R001
go run ./cmd/measurement -resolvers /path/to/selected.csv -config config/measurement_cases.json -only R001
```

Only `-execute` sends DNS traffic. Use a fresh run ID and a small address set for a new experiment. The source contains the historical test domain and authority addresses, which must be adapted to a domain under the new experimenter's control. A new run is separate from the four historical main runs.

## Evidence boundaries

The supplied source, profiles and derived results explain the measurement programs and show selected outputs of both phases. Raw laboratory event logs and raw public measurements are retained separately. The exact laboratory executable and complete historical service state were not preserved. The public measurement source changed after execution, so its present bytes cannot establish the exact binary used in the four main runs. A fresh run cannot reproduce the behavior of the original public endpoints at the original time.

The public main-run analysis associates unique-name cases with authoritative questions by name and type. Fixed-name cases support aggregate packet counts rather than one-to-one client-to-authority pairing. Capture tails in runs 1 and 4, unavailable contemporaneous drop counters and uncorrected client/server clock offset limit claims about absent packets. The Byteful DNSSEC label is external metadata, not a verified validation setting. The laboratory's positive NSEC3 hashed-owner reply is an observed reference exception under the preserved zone context.

No private signing keys, credentials, raw public address lists or packet captures are included. New run outputs and address lists must be reviewed separately before publication.
