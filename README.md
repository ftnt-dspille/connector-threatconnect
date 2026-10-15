# ThreatConnect - FortiSOAR connector

A FortiSOAR connector for the ThreatConnect v3 REST API. Look up indicator reputation, create,
update and delete indicators, flag false positives, browse owners, groups and tags, pull indicators
in bulk, and run scheduled threat-intel ingestion into the FortiSOAR Threat Intel Feeds module.

Any other endpoint can be called with **Invoke ThreatConnect REST API**, which signs the request for
you (HMAC or API token) and refuses a full URL, so credentials only ever go to the configured server.

## Install

Download `threatconnect-<version>.tgz` from the latest release and install it from the Connectors
page (Import Connector), or build it with `scripts/package.sh`.

## Configure

| Field | Meaning |
|---|---|
| Server URL | For example `https://app.threatconnect.com` |
| Authentication Type | **HMAC (Access ID + Secret Key)**, or **Bearer Token** (an API token or Personal Access Token, sent as `Authorization: TC-Token <token>`) |
| Default Organization | Owner used when an action does not pass one |
| Verify SSL | Verify the server certificate |
| TAXII Username / Password | The TAXII user, for the STIX/TAXII actions only (HTTP Basic) |
| TAXII Base Path | `/api/services/taxii/v2/taxii` (TAXII Server App 2.0, default) or `/api/services/taxii/v1` (App 1.0) |

## Actions

| Action | Endpoint |
|---|---|
| Get IP / File / Email / URL / Host Reputation | `GET /v3/indicators/{value}` |
| Get Indicator | `GET /v3/indicators/{id or summary}` |
| List Indicator | `GET /v3/indicators` |
| Fetch Indicators (Bulk) | `GET /v3/indicators` with TQL and paging |
| Create Indicator | `POST /v3/indicators` |
| Update Indicator | `PUT /v3/indicators/{id or summary}` |
| Delete Indicator | `DELETE /v3/indicators/{id or summary}` |
| Mark False Positive | `PUT /v3/indicators/{id}?fields=falsePositives` |
| Add Observation | `PUT /v3/indicators/{id}?fields=observations` |
| List Deleted Indicators | `GET /v3/indicators/deleted` |
| List Owners | `GET /v3/security/owners` |
| List Groups / Get Group | `GET /v3/groups[/{id}]` |
| List Tags | `GET /v3/tags` |
| Invoke ThreatConnect REST API | any path on the server |
| List TAXII Collections | `GET {taxii}/tc_taxii/collections` (one collection per owner) |
| Get TAXII Objects | `GET {taxii}/tc_taxii/collections/{id or owner}/objects` (one page, as sent) |
| Fetch STIX Indicators (Bulk) | the same, following `more`/`next`, returned in the v3 record shape |

The endpoints are from ThreatConnect's v3 and TAXII 2.1 documentation (docs.threatconnect.com).

## STIX / TAXII ingestion

ThreatConnect's TAXII Server Service App serves a collection per owner as STIX 2.1. Create a TAXII user,
put it in the **TAXII** fields above, and schedule `ThreatConnect > STIX Ingest`; it is the connector's only ingestion. Each STIX indicator pattern
(`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file` hashes) becomes an Address, Host, URL,
EmailAddress or File record; the TLP marking, confidence, owner and `x_threatconnect_id` ride along. Other
pattern types are skipped and counted. `added_after` is undocumented by ThreatConnect, so the connector
applies the cursor itself as well and works whether or not the server honours it.

## Authentication notes

The HMAC signature covers the **full request target, query string included**:
`path+query:method:timestamp`. Signing the path alone makes every filtered call a 401. The token
scheme is `TC-Token`; `Bearer` is not a ThreatConnect scheme. Both are checked by the test mock.

## Sample playbooks

`Sample - ThreatConnect - 2.3.0` holds inactive lookup and change samples, and the active STIX ingestion
playbooks (`Get STIX Indicators`, `> ThreatConnect > STIX Fetch and Create`, `ThreatConnect > STIX Ingest`).
STIX Ingest keeps a last-pull-time macro, calls STIX Fetch and Create, and moves the macro forward. Schedule
it for a recurring pull. The source is `playbooks/threatconnect.yaml`; `scripts/build_playbooks.sh` compiles
it (needs the fsrpb compiler).

## Tests

```bash
pip install -r tests/requirements.txt
pytest
```

The tests run every action over real HTTP against `tests/mock_threatconnect.py`, a small ThreatConnect
v3 and TAXII 2.1 server that **verifies** the HMAC signature, the token scheme and the TAXII user's Basic credentials. Nothing needs a ThreatConnect
account. The mock follows ThreatConnect's documentation; it has not been checked against a live tenant.

## License

MIT. Parts of the source carry the original Fortinet copyright header.
