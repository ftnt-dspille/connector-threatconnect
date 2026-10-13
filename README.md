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

The endpoints are from ThreatConnect's v3 documentation (docs.threatconnect.com).

## Authentication notes

The HMAC signature covers the **full request target, query string included**:
`path+query:method:timestamp`. Signing the path alone makes every filtered call a 401. The token
scheme is `TC-Token`; `Bearer` is not a ThreatConnect scheme. Both are checked by the test mock.

## Sample playbooks

`Sample - ThreatConnect - 2.2.1` holds inactive lookup and change samples, and the active ingestion
playbooks (`Get Indicators`, `ThreatConnect > Fetch and Create`, `ThreatConnect > Ingest`). Ingest keeps
a last-pull-time macro, calls Fetch and Create, and moves the macro forward. The source is
`playbooks/threatconnect.yaml`; `scripts/build_playbooks.sh` compiles it (needs the fsrpb compiler).

## Tests

```bash
pip install -r tests/requirements.txt
pytest
```

The tests run every action over real HTTP against `tests/mock_threatconnect.py`, a small ThreatConnect
v3 server that **verifies** the HMAC signature and the token scheme. Nothing needs a ThreatConnect
account. The mock follows ThreatConnect's documentation; it has not been checked against a live tenant.

## License

MIT. Parts of the source carry the original Fortinet copyright header.
