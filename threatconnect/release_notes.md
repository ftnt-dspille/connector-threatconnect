#### The following enhancements have been made to the ThreatConnect connector in version 2.2.1:
- Fixed: the Owner dropdown showed "[object Object]" for every entry in the step editor. It now lists the owner names.

#### The following enhancements have been made to the ThreatConnect connector in version 2.2.0:

##### What's Added

- Added operations: **Get Indicator**, **Create Indicator**, **Update Indicator**, **Delete Indicator**, **Mark False Positive**, **Add Observation**, **List Deleted Indicators**, **List Owners**, **List Groups**, **Get Group** and **List Tags**.
- **Invoke ThreatConnect REST API** now takes a method (GET, POST, PUT, DELETE) and a JSON request body. The request is signed or token-authenticated for you, and a full URL is refused so credentials never leave the configured server.
- Owner fields are dropdowns filled from your ThreatConnect owners (you can still type a name).
- Sample playbooks: Create Indicator, Update Indicator, Mark False Positive and List Owners. The collection now holds the lookups, the new samples and the ingestion playbooks together.

##### Improvements

- Requests time out after 60 seconds instead of hanging, and reads are retried on 429 and gateway errors. Writes are never retried.
- Errors name the method, path and ThreatConnect's own message, for example `HTTP 404 GET /api/v3/indicators/x: Indicator x not found`.
- An action with no owner and no Default Organization no longer fails.
- Quotes in an owner or type no longer break the TQL filter used by bulk pulls.
- Ingestion lands file indicators as `FileHash-MD5`, `FileHash-SHA1` or `FileHash-SHA256` by hash length (they were all SHA256), and a file with several hashes is stored by its strongest one.

#### The following fixes have been made to the ThreatConnect connector in version 2.1.1:

##### Bug fixes

- **Reverted the 2.1.0 "path-only" HMAC signing change.** ThreatConnect's documented HMAC scheme signs the full request target -- path AND query string (`path+query:method:timestamp`; see the "Access ID and Secret Key" section of ThreatConnect's REST API Quick Start, whose own example includes the query string, and the tcex SDK docs: "the authorization string has to be built after the URI and query parameters are built and before the request is sent"). Signing path-only made every filtered request -- reputation hunts, listing, ingestion pulls, even the health check -- a guaranteed signature mismatch (401) against a live tenant. The sporadic mismatches that motivated the 2.1.0 change were an encoding issue, not a signing-scope issue; they are addressed at the source instead (next bullet).
- Percent-encodes the `owner` query parameter with `urllib.parse.quote` rather than a space-only `.replace(" ", "%20")`, so owners containing `&`, `=`, `#`, or non-ASCII characters no longer corrupt the query string (and the signature with it). Spaces still encode as `%20`, exactly as in the docs' example.
- **The `Bearer Token` authentication mode now sends `Authorization: TC-Token <token>`.** ThreatConnect's documented token scheme -- for API tokens and Personal Access Tokens alike -- is `TC-Token`, not `Bearer` (the `Bearer` scheme appears nowhere in TC's documentation). The `Bearer Token` picklist label is unchanged so existing configurations migrate unchanged; only the wire header changed.

#### The following enhancements have been made to the ThreatConnect connector in version 2.1.0:

##### What's Added

- Added an `Authentication Type` configuration picklist:
    - `HMAC (Access ID + Secret Key)` -- existing per-request signature authentication.
    - `Bearer Token` -- ThreatConnect Personal Access Token, sent as `Authorization: Bearer <token>`.
- Added scheduled **data ingestion** support:
    - Ingestion configuration includes indicator-type filter, owner filter, last-pull datetime watermark, default reputation / TLP / confidence / expiry, and a per-run cap.
    - `ingest_mapping_template` maps ThreatConnect indicator records to the FortiSOAR Indicators module.
- Added a new operation **Fetch Indicators (Bulk)** that paginates `/api/v3/indicators` with optional TQL filters (`typeName`, `ownerName`, `lastModified`). Page size is capped at the ThreatConnect limit of 1000. Used by data ingestion and available on-demand.

##### What's Improved

- The HMAC signer now signs the path-only portion of each endpoint, ignoring any query string -- the prior behavior of including the query string in the signed message could cause sporadic signature mismatches on filtered requests.
- The `Default Organization` configuration field is no longer marked required; it is now used only as a fallback when an action does not pass an explicit owner.
- Description and tooltips updated to reflect the v3 API surface and the new authentication options.

#### Breaking changes

- Existing configurations are migrated automatically: `Authentication Type` defaults to `HMAC (Access ID + Secret Key)`, preserving the prior behavior with the existing `Access ID` and `Secret Key` values.

#### Version 2.0.0 -- What's Added

- Added the following operations and playbooks:
  - List Indicator
  - Invoke ThreatConnect REST API

#### Version 2.0.0 -- What's Improved

- Updated the connector to version 3 of the ThreatConnect REST API, and therefore updated all the actions to use this version of the API.
- Renamed the following actions and added a new input parameter named "Include Additional Params":
  - Hunt Email renamed to Get Email Reputation
  - Hunt File Hash renamed to Get File Reputation
  - Hunt Host renamed to Get Host Reputation
  - Hunt IP renamed to Get IP Reputation
  - Hunt URL renamed to Get URL Reputation
