"""Mock ThreatConnect v3 REST API -- the vendor side of a threat-feed ingest.

Serves the surface the FortiSOAR ``threatconnect`` connector actually calls
(``threatconnect/operations.py``), over plain HTTP. Put a TLS-terminating
reverse proxy in front of it when a FortiSOAR needs to reach it with
"Verify SSL" on.

Endpoints (all JSON, every success carries ``status: "Success"``
because the connector does ``result['status'].lower()`` on every reply and a
missing key reads as a parse error, not a failure):

  /api/v3/indicators?resultStart=0&resultLimit=1[&fields=...][&tql=...]
      list + bulk-pull + health-check endpoint. Honours the TQL clauses the
      connector emits (typeName = "...", ownerName = "...", lastModified >=
      "...") joined by AND, paged by resultStart/resultLimit.
  /api/v3/indicators/{value}
      reputation lookup by exact indicator value.
  POST   /api/v3/indicators                 create (an existing summary in the
                                            same owner is updated, per the docs)
  PUT    /api/v3/indicators/{id or summary} update; ?fields=falsePositives and
                                            ?fields=observations; tags and
                                            securityLabels honour ``mode``
  DELETE /api/v3/indicators/{id or summary} soft delete
  GET    /api/v3/indicators/deleted         deleted indicators (deletedSince)
  GET    /api/v3/security/owners[/{id}]     owners
  GET    /api/v3/groups[/{id}]              groups (tql typeName / name)
  GET    /api/v3/tags[/{id}]                tags

Auth mirrors ThreatConnect's DOCUMENTED schemes and is VERIFIED (not just
echoed), so the mock exercises the signing logic rather than bypassing it:

  HMAC   Authorization: "TC {access_id}:{b64(hmac_sha256(secret,
                            "{path+query}:{method}:{timestamp}"))}" + Timestamp
         header. The signature covers the request target exactly as received,
         per TC's Quick Start ("the API path and query strings ... as follows:
                         /api/v2/indicators/hosts/example.com?Owner=Common%20Community:GET:1513703787")
         and tcex ("built after the URI and query parameters are built").
         A client that signs the path only -- or pre-mangles the query before
         signing -- gets a 401, exactly as live ThreatConnect answers it.
         The Timestamp nonce must be within five minutes of server time.
  PAT    Authorization: "TC-Token {pat}" -- ThreatConnect's documented token
         scheme (Quick Start > API Token). "Bearer" is NOT a ThreatConnect
         scheme and is rejected, so a connector regression to it fails here
         instead of at the customer.

Response fidelity (per the v3 retrieve docs):

  * list endpoint returns {"status": "Success", "data": [ ... ]},
  * single-object lookup /api/v3/indicators/{id or summary} returns
    {"status": "Success", "data": { ... }} -- data as the OBJECT -- and 404s
    with {"status": "Error", ...} for an unknown value,
  * error statuses are "Error" (never "Failure"), matching the docs' wording.

TAXII 2.1 / STIX (ThreatConnect TAXII Server Service App; docs.threatconnect.com
> REST API > TAXII 2.1). The same indicator corpus, served as STIX 2.1 under
``/api/services/taxii/v2/taxii`` (App v2.0) and ``/api/services/taxii/v1`` (App
v1.0, which adds ``/manifest``). HTTP Basic with a TAXII user, and
``Accept: application/taxii+json;version=2.1``; neither the HMAC nor the token
scheme is accepted there, and Basic is not accepted on /api/v3:

  /taxii2                                         discovery
  /tc_taxii                                       API root
  /tc_taxii/collections[/{id|ownerName}]          one collection per owner
  /tc_taxii/collections/{c}/objects?limit&next    {more, next, objects}
  /tc_taxii/collections/{c}/manifest              v1 prefix only

``added_after`` is NOT documented by ThreatConnect, so the mock can behave either
way (``--taxii-no-added-after`` makes it ignore the parameter) and a consumer
must not depend on it.

Stdlib only. Growable (``--grow-every``) so a scheduled incremental pull has
new records to find; growth is in-memory and resets on restart, which a
tolerant feed consumer must survive.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import threading
import time
import uuid
import zlib
from base64 import b64decode, b64encode
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

NS = uuid.uuid5(uuid.NAMESPACE_DNS, "fsr-lab-threatconnect-grow")
PAGE_CAP = 1000
DEFAULT_PAGE = 500
_GROW_LOCK = threading.Lock()


def build_hmac_header(access_id: str, secret_key: str, endpoint: str,
                      method: str = "GET", timestamp: int | None = None) -> dict:
    """Sign the REQUEST TARGET AS TRANSMITTED -- path + query string -- the way
    ThreatConnect's documented scheme does (``path+query:method:timestamp``;
    the docs' own example includes the query string, and the tcex SDK states
    the string "has to be built after the URI and query parameters are built
    and before the request is sent")."""
    ts = int(timestamp if timestamp is not None else time.time())
    message = f"{endpoint}:{method}:{ts}".encode()
    sig = b64encode(hmac.new(secret_key.encode(), message, hashlib.sha256).digest()).decode()
    return {"Timestamp": str(ts), "Authorization": f"TC {access_id}:{sig}"}


def _parse_dt(value: str) -> float | None:
    """Accept the shapes the Ingest workflow's lastPullTime macro can carry."""
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(
            value.strip().replace("Z", "+00:00").replace(" ", "T", 1)
        ).timestamp()
    except ValueError:
        return None


OWNERS = [
    {"id": 1, "name": "FortiLab Org", "type": "Organization", "ownerRole": "Organization Administrator",
     "permIndicator": "CUD", "permGroup": "CUD", "permTag": "CUD"},
    {"id": 2, "name": "Common Community", "type": "Community", "ownerRole": "Community Member",
     "permIndicator": "R", "permGroup": "R", "permTag": "R"},
    {"id": 3, "name": "Lab Source", "type": "Source", "ownerRole": "Source Contributor",
     "permIndicator": "CUD", "permGroup": "CUD", "permTag": "R"},
]
GROUPS = [
    {"id": 101, "name": "Lab Adversary One", "type": "Adversary", "ownerName": "FortiLab Org",
     "dateAdded": "2026-10-01T00:00:00Z", "webLink": "https://example.invalid/g/101"},
    {"id": 102, "name": "Lab Incident 7", "type": "Incident", "ownerName": "FortiLab Org",
     "dateAdded": "2026-10-02T00:00:00Z", "webLink": "https://example.invalid/g/102"},
    {"id": 103, "name": "Lab Report Q3", "type": "Report", "ownerName": "Common Community",
     "dateAdded": "2026-10-03T00:00:00Z", "webLink": "https://example.invalid/g/103"},
]
SUMMARY_FIELDS = {"Address": "ip", "EmailAddress": "address", "Host": "hostName", "URL": "text"}
HASH_FIELDS = ("md5", "sha1", "sha256")
TYPES = {"Address", "EmailAddress", "File", "Host", "URL", "ASN", "CIDR", "Mutex", "Hashtag",
         "Email Subject", "Registry Key", "User Agent"}


def summary_for(body: dict) -> str | None:
    """The indicator's summary from a create body, or None when a required field is missing."""
    kind = body.get("type")
    if kind == "File":
        parts = [body[h] for h in HASH_FIELDS if body.get(h)]
        return " : ".join(parts) if parts else None
    field = SUMMARY_FIELDS.get(kind)
    return body.get(field) if field else None


# -- STIX / TAXII --------------------------------------------------------------
TAXII_MEDIA = "application/taxii+json;version=2.1"
TAXII_PREFIXES = ("/api/services/taxii/v2/taxii", "/api/services/taxii/v1")
TAXII_V1 = "/api/services/taxii/v1"
TAXII_DEFAULT_PAGE = 100
TAXII_PAGE_CAP = 1000
NS_TAXII = uuid.uuid5(uuid.NAMESPACE_DNS, "fsr-lab-threatconnect-taxii")
# The fixed STIX 2.1 TLP marking-definition ids (OASIS STIX 2.1 section 7.2.1.4).
TLP_MARKINGS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
TLP_ORDER = ("white", "green", "amber", "red")
HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
STIX_OBJECT = {"Address": None, "Host": "domain-name", "URL": "url", "EmailAddress": "email-addr"}


def _stix_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _iso_ms(value: str | None) -> str:
    ts = _parse_dt(value or "")
    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{int((ts % 1) * 1000):03d}Z"


def stix_pattern(row: dict) -> str | None:
    """The STIX pattern for a ThreatConnect indicator, or None for a type with no mapping."""
    kind, summary = row.get("type"), str(row.get("summary") or "")
    if kind == "File":
        parts = []
        for h in (x.strip() for x in summary.split(" : ")):
            name = HASH_NAMES.get(len(h))
            if name:
                parts.append(f"file:hashes.'{name}' = '{_stix_quote(h)}'")
        return "[" + " AND ".join(parts) + "]" if parts else None
    if kind == "Address":
        obj = "ipv6-addr" if ":" in summary else "ipv4-addr"
    else:
        obj = STIX_OBJECT.get(kind)
    return f"[{obj}:value = '{_stix_quote(summary)}']" if obj else None


def tlp_for(row: dict) -> str:
    """A stable TLP per indicator: the corpus carries none, and a feed consumer must read one."""
    return TLP_ORDER[zlib.crc32(str(row.get("id")).encode()) % 4]


def marking_definition(name: str) -> dict:
    return {"type": "marking-definition", "spec_version": "2.1", "id": TLP_MARKINGS[name],
            "created": "2017-01-20T00:00:00.000Z", "name": f"TLP:{name.upper()}",
            "definition_type": "tlp", "definition": {"tlp": name}}


def stix_indicator(row: dict, tcid) -> dict | None:
    pattern = stix_pattern(row)
    if pattern is None:
        return None
    obj = {
        "type": "indicator", "spec_version": "2.1",
        "id": "indicator--" + str(uuid.uuid5(NS_TAXII, str(row["id"]))),
        "created": _iso_ms(row.get("dateAdded")), "modified": _iso_ms(row.get("lastModified")),
        "name": row.get("summary"), "pattern": pattern, "pattern_type": "stix", "pattern_version": "2.1",
        "valid_from": _iso_ms(row.get("dateAdded")),
        "confidence": int(row.get("confidence") or 0),
        "object_marking_refs": [TLP_MARKINGS[tlp_for(row)]],
        "x_threatconnect_id": tcid,
        "x_threatconnect_owner": row.get("ownerName"),
        "x_threatconnect_type": row.get("type"),
        "x_threat_rating": int(round(float(row.get("rating") or 0))),
    }
    if row.get("description"):
        obj["description"] = row["description"]
    if row.get("tags"):
        obj["labels"] = sorted({str(t) for t in row["tags"]})
    return obj


def collection_id(owner: str) -> str:
    return str(uuid.uuid5(NS_TAXII, "collection:" + owner))


class Dataset:
    """Thread-safe indicator store with TQL-lite filtering."""

    def __init__(self, rows: list[dict]):
        self.rows = list(rows)
        self.deleted: list[dict] = []
        self.next_id = 100000
        # ThreatConnect's own ids are integers (x_threatconnect_id); the corpus keys rows by uuid.
        self.tcids: dict[str, int] = {}
        for r in self.rows:
            self.tcid(r)

    def tcid(self, row: dict) -> int:
        if isinstance(row.get("id"), int):
            return row["id"]
        with _GROW_LOCK:
            return self.tcids.setdefault(str(row.get("id")), 1000 + len(self.tcids))

    def owners(self) -> list[str]:
        with _GROW_LOCK:
            return sorted({r.get("ownerName") for r in self.rows if r.get("ownerName")})

    def add(self, row: dict) -> None:
        with _GROW_LOCK:
            self.rows.append(row)

    def grow(self, count: int, seq: int) -> None:
        now = datetime.now(timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        for k in range(count):
            i = seq * count + k
            with _GROW_LOCK:
                base = len(self.rows)
            row = {
                "id": str(uuid.uuid5(NS, f"grow-{i}")),
                "type": ["Address", "Host", "URL"][i % 3],
                "summary": f"198.51.100.{(i % 250) + 1}" if i % 3 == 0
                else (f"grow-host-{i:04d}.example.com" if i % 3 == 1
                      else f"https://example.com/grow/{i:04d}"),
                # rating is a float in real TC responses (docs: 3.00)
                "rating": 3.0,
                "confidence": 55 + (i % 40),
                "ownerName": "FortiLab Org",
                "dateAdded": now_iso,
                "lastModified": now_iso,
                "threatAssess": {"rating": 3.0, "confidence": 55 + (i % 40), "count": 1},
                "description": f"Grown lab indicator {i} (fresh lastModified)",
                "tags": ["Phishing"],
            }
            # uuid5 ids collide-free by construction, so plain append is safe;
            # the lock guards list mutation only.
            with _GROW_LOCK:
                self.rows.append(row)
            self.tcid(row)

    def query(self, type_: str | None, owner: str | None,
              modified_since: str | None) -> list[dict]:
        cutoff = _parse_dt(modified_since) if modified_since else None
        out = []
        with _GROW_LOCK:
            snapshot = list(self.rows)
        for r in snapshot:
            if type_ and (r.get("type") or "").lower() != type_.lower():
                continue
            if owner and (r.get("ownerName") or "").lower() != owner.lower():
                continue
            if cutoff is not None:
                lm = _parse_dt(r.get("lastModified", ""))
                if lm is None or lm < cutoff:
                    continue
            out.append(r)
        return out

    def find(self, ident: str) -> dict | None:
        cands = {ident, unquote(ident), unquote(ident.replace("+", "%20"))}
        with _GROW_LOCK:
            snapshot = list(self.rows)
        for r in snapshot:
            if str(r.get("id")) == ident:
                return r
            if (r.get("summary") or "") in cands or \
               (r.get("summary") or "").casefold() in {c.casefold() for c in cands}:
                return r
        return None

    def count(self) -> int:
        with _GROW_LOCK:
            return len(self.rows)


class Handler(BaseHTTPRequestHandler):
    ds: Dataset
    access_id: str
    secret_key: str
    pat: str
    taxii_user: str = "test-taxii"
    taxii_pass: str = "test-taxii-pass"  # pragma: allowlist secret
    taxii_added_after: bool = True
    no_auth: bool = False

    server_version = "TC-Mock/1.0"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)

    # -- auth ---------------------------------------------------------------
    def _authed(self, method: str) -> bool:
        """Enforce the DOCUMENTED schemes, strictly.

        HMAC  ``Authorization: TC {access_id}:{b64(hmac_sha256(secret,
              "{path+query}:{method}:{timestamp}"))}`` + ``Timestamp`` header.
              The signature covers the full request target exactly as received
              -- a client that signs the path only (or pre-cleans the query)
              gets a 401, matching live ThreatConnect. The Timestamp nonce
              must be within five minutes of server time, per the docs.
        PAT   ``Authorization: TC-Token {pat}`` -- TC's documented token scheme,
              for API tokens and Personal Access Tokens alike. ``Bearer`` is
              not a ThreatConnect scheme and is rejected.
        """
        if self.no_auth:
            return True
        header = self.headers.get("Authorization", "")
        if header == f"TC-Token {self.pat}":
            return True
        m = re.match(r"^TC ([^:]+):(.+)$", header)
        if not m:
            return False
        ts_raw = self.headers.get("Timestamp", "")
        try:
            ts = int(ts_raw)
        except ValueError:
            return False
        if abs(time.time() - ts) > 300:
            return False
        expected = build_hmac_header(m.group(1), self.secret_key, self.path, method,
                                     timestamp=ts)
        return hmac.compare_digest(expected["Authorization"], header)

    # -- http ---------------------------------------------------------------
    def do_GET(self):
        taxii = urlparse(self.path)
        for prefix in TAXII_PREFIXES:
            if taxii.path.startswith(prefix + "/"):
                return self._taxii(prefix, taxii)
        if not self._authed("GET"):
            return self._send(401, {"status": "Error", "message": "Unauthorized"})
        parsed = urlparse(self.path)
        path_only = parsed.path.rstrip("/")
        if path_only == "/api/v3/indicators":
            return self._indicators_list(parse_qs(parsed.query))
        if path_only == "/api/v3/indicators/deleted":
            return self._deleted(parse_qs(parsed.query))
        if path_only.startswith("/api/v3/security/owners"):
            return self._owners(path_only)
        if path_only.startswith("/api/v3/groups"):
            return self._groups(path_only, parse_qs(parsed.query))
        if path_only.startswith("/api/v3/tags"):
            return self._tags(path_only)
        if self._is_lookup(parsed.path):
            return self._indicators_lookup(parsed)
        return self._send(404, {"status": "Error",
                                "message": f"Unknown endpoint: {parsed.path}"})

    def _is_lookup(self, path: str) -> bool:
        return path.startswith("/api/v3/indicators/") and len(path) > len("/api/v3/indicators/")

    def _indicators_lookup(self, parsed):
        prefix = "/api/v3/indicators/"
        # Substring-strip, NOT split(): URL indicators carry '/' inside the
        # value, so join-and-drop-segments corrupts them.
        ident = parsed.path[len(prefix):] if parsed.path.startswith(prefix) else ""
        hits = self.ds.find(ident)
        # Real TC returns ``data`` as the INDICATOR OBJECT for this endpoint
        # (retrieve docs: ``GET /v3/indicators/{id or summary}`` -> ``"data": {...}``),
        # and 404s with an Error status for an unknown value -- not an empty
        # list. The connector surfaces that 401/404 as a ConnectorError, which
        # is the behaviour hunt playbooks must tolerate against the real tenant.
        if not hits:
            return self._send(404, {"status": "Error",
                                    "message": f"Indicator {ident} not found"})
        self._send(200, {"status": "Success", "data": hits})

    def _indicators_list(self, q: dict):
        first = {k: (v[-1] if isinstance(v, list) else v) for k, v in q.items()}
        try:
            start = max(0, int(first.get("resultStart", 0)))
        except ValueError:
            start = 0
        try:
            limit = int(first.get("resultLimit", DEFAULT_PAGE))
        except (TypeError, ValueError):
            limit = DEFAULT_PAGE
        limit = max(1, min(limit, PAGE_CAP))

        type_ = owner = since = None
        tql = first.get("tql", "")
        if tql:
            for clause in re.split(r"\s+AND\s+", tql):
                m = re.match(r'\s*(\w+)\s*(>=|=)\s*"((?:[^"\\]|\\.)*)"\s*$', clause.strip())
                if not m:
                    continue
                key, _, val = m.groups()
                val = re.sub(r"\\(.)", r"\1", val)  # TQL escapes: \" and \\
                if key == "typeName":
                    type_ = val
                elif key == "ownerName":
                    owner = val
                elif key == "lastModified":
                    since = val
        rows = self.ds.query(type_, owner, since)
        page = rows[start:start + limit]
        self._send(200, {
            "status": "Success",
            "data": page,
            "count": len(rows),
            "resultCount": len(page),
            "resultStart": start,
        })


    # -- TAXII 2.1 --------------------------------------------------------------
    def _taxii_error(self, code: int, title: str):
        extra = {"WWW-Authenticate": 'Basic realm="ThreatConnect TAXII"'} if code == 401 else None
        self._send(code, {"title": title, "http_status": str(code)}, TAXII_MEDIA, extra)

    def _taxii_authed(self) -> bool:
        if self.no_auth:
            return True
        want = "Basic " + b64encode(f"{self.taxii_user}:{self.taxii_pass}".encode()).decode()
        return hmac.compare_digest(self.headers.get("Authorization", ""), want)

    def _taxii(self, prefix: str, parsed):
        if not self._taxii_authed():
            return self._taxii_error(401, "Unauthorized")
        if "application/taxii+json" not in self.headers.get("Accept", ""):
            return self._taxii_error(
                406, "Not Acceptable: send Accept: application/taxii+json;version=2.1")
        rel = parsed.path[len(prefix):].rstrip("/")
        q = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        host = self.headers.get("Host", "localhost")
        origin = f"{self.headers.get('X-Forwarded-Proto', 'https')}://{host}"
        root = f"{origin}{prefix}/tc_taxii"
        if rel == "/taxii2":
            return self._send(200, {"title": "ThreatConnect TAXII 2.1 Server", "api_roots": [root],
                                    "default": root}, TAXII_MEDIA)
        if rel == "/tc_taxii":
            return self._send(200, {"title": "ThreatConnect TAXII 2.1 Server",
                                    "description": "Lab mock of the ThreatConnect TAXII Server Service App",
                                    "versions": [TAXII_MEDIA], "max_content_length": 104857600},
                              TAXII_MEDIA)
        if rel == "/tc_taxii/collections":
            return self._send(200, {"collections": [self._collection(o) for o in self.ds.owners()]},
                              TAXII_MEDIA)
        m = re.match(r"^/tc_taxii/collections/([^/]+)(?:/(objects|manifest))?$", rel)
        if not m:
            return self._taxii_error(404, f"Unknown endpoint: {parsed.path}")
        owner = self._owner_for(unquote(m.group(1)))
        if owner is None:
            return self._taxii_error(404, f"Collection {unquote(m.group(1))} not found")
        if not m.group(2):
            return self._send(200, self._collection(owner), TAXII_MEDIA)
        if m.group(2) == "manifest" and prefix != TAXII_V1:
            return self._taxii_error(404, "manifest is available on App v1.0 only")
        self._taxii_objects(owner, q, manifest=m.group(2) == "manifest")

    def _owner_for(self, ident: str) -> str | None:
        for o in self.ds.owners():
            if ident == collection_id(o) or ident.casefold() == o.casefold():
                return o
        return None

    def _collection(self, owner: str) -> dict:
        return {"id": collection_id(owner), "title": owner, "description": f"Indicators owned by {owner}",
                "can_read": True, "can_write": False, "media_types": [TAXII_MEDIA],
                "x_tql": f'(ownerName EQ "{owner}") AND typeName in ("Address","EmailAddress","File","Host","URL")'}

    def _taxii_objects(self, owner: str, q: dict, manifest: bool):
        try:
            limit = max(1, min(int(q.get("limit", TAXII_DEFAULT_PAGE)), TAXII_PAGE_CAP))
            start = max(0, int(q.get("next", 0)))
        except ValueError:
            return self._taxii_error(400, "limit and next must be integers")
        rows = self.ds.query(None, owner, None)
        if self.taxii_added_after and q.get("added_after"):
            cutoff = _parse_dt(q["added_after"])
            if cutoff is None:
                return self._taxii_error(400, "added_after must be a timestamp")
            rows = [r for r in rows if (_parse_dt(r.get("lastModified", "")) or 0) > cutoff]
        rows.sort(key=lambda r: (r.get("lastModified", ""), str(r.get("id"))))
        page = rows[start:start + limit]
        more = start + limit < len(rows)
        if manifest:
            out = [{"id": "indicator--" + str(uuid.uuid5(NS_TAXII, str(r["id"]))),
                    "version": _iso_ms(r.get("lastModified")), "date_added": _iso_ms(r.get("lastModified")),
                    "media_types": TAXII_MEDIA} for r in page]
        else:
            indicators = [i for i in (stix_indicator(r, self.ds.tcid(r)) for r in page) if i]
            markings, seen = [], set()
            for i in indicators:
                for ref in i["object_marking_refs"]:
                    if ref not in seen:
                        seen.add(ref)
                        markings.append(marking_definition(next(k for k, v in TLP_MARKINGS.items() if v == ref)))
            out = markings + indicators
        body: dict = {"more": more}
        if more:
            body["next"] = str(start + limit)
        if out:  # the spec omits "objects" when there is nothing to return
            body["objects"] = out
        self._send(200, body, TAXII_MEDIA)

    # -- writes ---------------------------------------------------------------
    def _body(self) -> dict | None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return None

    def do_POST(self):
        if not self._authed("POST"):
            return self._send(401, {"status": "Error", "message": "Unauthorized"})
        parsed = urlparse(self.path)
        if parsed.path.rstrip("/") != "/api/v3/indicators":
            return self._send(405, {"status": "Error", "message": "Method Not Allowed"})
        body = self._body()
        if not isinstance(body, dict):
            return self._send(400, {"status": "Error", "message": "Body must be a JSON object"})
        if body.get("type") not in TYPES:
            return self._send(400, {"status": "Error", "message": "Unknown or missing indicator type"})
        summary = summary_for(body)
        if not summary:
            return self._send(400, {"status": "Error", "message": "Missing the required field for type %s" % body["type"]})
        q = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        owner = body.get("ownerName") or q.get("owner") or "FortiLab Org"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with _GROW_LOCK:
            row = next((r for r in self.ds.rows if r["summary"] == summary and r.get("ownerName") == owner), None)
            created = row is None
            if created:
                self.ds.next_id += 1
                row = {"id": self.ds.next_id, "type": body["type"], "summary": summary, "ownerName": owner,
                       "dateAdded": now, "rating": 0.0, "confidence": 0, "tags": [], "securityLabels": []}
                self.ds.rows.append(row)
            self._apply(row, body, now)
        self._send(201 if created else 200, {"status": "Success", "message": "Created" if created else "Updated", "data": row})

    def do_PUT(self):
        if not self._authed("PUT"):
            return self._send(401, {"status": "Error", "message": "Unauthorized"})
        parsed = urlparse(self.path)
        ident = parsed.path[len("/api/v3/indicators/"):] if parsed.path.startswith("/api/v3/indicators/") else ""
        row = self.ds.find(ident) if ident else None
        if row is None:
            return self._send(404, {"status": "Error", "message": "Indicator %s not found" % ident})
        body = self._body()
        if not isinstance(body, dict):
            return self._send(400, {"status": "Error", "message": "Body must be a JSON object"})
        fields = parse_qs(parsed.query).get("fields", [])
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with _GROW_LOCK:
            if "falsePositives" in fields:
                row["falsePositiveFlag"] = bool(body.get("falsePositiveFlag"))
                row["falsePositiveCount"] = row.get("falsePositiveCount", 0) + (1 if body.get("falsePositiveFlag") else 0)
            elif "observations" in fields:
                row["observationCount"] = row.get("observationCount", 0) + int(body.get("observations", 1))
            else:
                self._apply(row, body, now)
            row["lastModified"] = now
        self._send(200, {"status": "Success", "message": "Updated", "data": row})

    def do_DELETE(self):
        if not self._authed("DELETE"):
            return self._send(401, {"status": "Error", "message": "Unauthorized"})
        parsed = urlparse(self.path)
        ident = parsed.path[len("/api/v3/indicators/"):] if parsed.path.startswith("/api/v3/indicators/") else ""
        row = self.ds.find(ident) if ident else None
        if row is None:
            return self._send(404, {"status": "Error", "message": "Indicator %s not found" % ident})
        with _GROW_LOCK:
            self.ds.rows.remove(row)
            row["deletedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.ds.deleted.append(row)
        self._send(200, {"status": "Success", "message": "Deleted"})

    @staticmethod
    def _apply(row: dict, body: dict, now: str) -> None:
        """Merge the writable fields of a create/update body into ``row``."""
        for key in ("rating", "confidence", "active", "description"):
            if key in body:
                row[key] = body[key]
        row["lastModified"] = now
        for key, name_key in (("tags", "tags"), ("securityLabels", "securityLabels")):
            block = body.get(key)
            if not isinstance(block, dict):
                continue
            names = [i.get("name") or i.get("techniqueId") for i in block.get("data", [])]
            mode = block.get("mode", "append")
            current = list(row.get(name_key) or [])
            if mode == "replace":
                current = names
            elif mode == "delete":
                current = [n for n in current if n not in names]
            else:
                current += [n for n in names if n not in current]
            row[name_key] = current
        if "threatAssess" in row:
            row["threatAssess"]["rating"] = row.get("rating", row["threatAssess"].get("rating"))

    # -- read-only extras -----------------------------------------------------
    def _deleted(self, q: dict):
        since = _parse_dt(q["deletedSince"][-1]) if q.get("deletedSince") else None
        kind = q["type"][-1] if q.get("type") else None
        rows = [r for r in self.ds.deleted
                if (not kind or r["type"] == kind) and (since is None or _parse_dt(r["deletedAt"]) >= since)]
        self._send(200, {"status": "Success", "data": rows, "count": len(rows)})

    def _owners(self, path_only: str):
        tail = path_only[len("/api/v3/security/owners"):].strip("/")
        if not tail:
            return self._send(200, {"status": "Success", "data": OWNERS, "count": len(OWNERS)})
        hit = next((o for o in OWNERS if str(o["id"]) == tail), None)
        if hit is None:
            return self._send(404, {"status": "Error", "message": "Owner %s not found" % tail})
        self._send(200, {"status": "Success", "data": hit})

    def _groups(self, path_only: str, q: dict):
        tail = path_only[len("/api/v3/groups"):].strip("/")
        if tail:
            hit = next((g for g in GROUPS if str(g["id"]) == tail), None)
            if hit is None:
                return self._send(404, {"status": "Error", "message": "Group %s not found" % tail})
            return self._send(200, {"status": "Success", "data": hit})
        rows = list(GROUPS)
        for clause in re.split(r"\s+AND\s+", (q.get("tql") or [""])[-1]):
            m = re.match(r'\s*(\w+)\s*=\s*"([^"]*)"\s*$', clause.strip())
            if m and m.group(1) in ("typeName", "name", "ownerName"):
                key = {"typeName": "type", "name": "name", "ownerName": "ownerName"}[m.group(1)]
                rows = [g for g in rows if g[key].lower() == m.group(2).lower()]
        self._send(200, {"status": "Success", "data": rows, "count": len(rows)})

    def _tags(self, path_only: str):
        names = sorted({t for r in self.ds.rows for t in (r.get("tags") or [])})
        tags = [{"id": 500 + i, "name": n, "owner": "FortiLab Org"} for i, n in enumerate(names)]
        tail = path_only[len("/api/v3/tags"):].strip("/")
        if tail:
            hit = next((t for t in tags if str(t["id"]) == tail), None)
            if hit is None:
                return self._send(404, {"status": "Error", "message": "Tag %s not found" % tail})
            return self._send(200, {"status": "Success", "data": hit})
        self._send(200, {"status": "Success", "data": tags, "count": len(tags)})

    def _send(self, code: int, payload: dict, ctype: str = "application/json",
              headers: dict | None = None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--dataset", default=str(Path(__file__).parent / "fixtures.json"))
    p.add_argument("--no-auth", action="store_true")
    p.add_argument("--taxii-no-added-after", action="store_true",
                   help="ignore the TAXII added_after parameter, as a server that does not implement it")
    p.add_argument("--grow-every", type=int, default=0,
                   help="seconds between batches of new indicators (0 = static)")
    p.add_argument("--grow-count", type=int, default=10)
    a = p.parse_args()

    rows = json.loads(Path(a.dataset).read_text())
    Handler.ds = Dataset(rows)
    Handler.access_id = os.environ.get("TC_ACCESS_ID", "test-access-id")
    Handler.secret_key = os.environ.get("TC_SECRET_KEY", "test-secret-key")
    Handler.pat = os.environ.get("TC_PAT", "test-pat")
    Handler.taxii_user = os.environ.get("TC_TAXII_USER", "test-taxii")
    Handler.taxii_pass = os.environ.get("TC_TAXII_PASS", "test-taxii-pass")  # pragma: allowlist secret
    Handler.taxii_added_after = not a.taxii_no_added_after
    Handler.no_auth = a.no_auth
    total = Handler.ds.count()

    if a.grow_every > 0:
        state = {"seq": 0}

        def _grow():
            while True:
                time.sleep(a.grow_every)
                state["seq"] += 1
                Handler.ds.grow(a.grow_count, state["seq"])

        threading.Thread(target=_grow, daemon=True).start()

    httpd = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"ThreatConnect mock: http://{a.host}:{a.port} ({total} indicators, "
          f"auth={'off' if a.no_auth else 'HMAC|Bearer|TAXII-Basic'}, "
          f"grow={'every ' + str(a.grow_every) + 's' if a.grow_every else 'static'})",
          flush=True)
    print("FSR connector config -> api_base_url: https://<proxy-host>:<port> "
          "(Verify TLS on), auth_type: 'HMAC (Access ID + Secret Key)', "
          "api_access_id: '<TC_ACCESS_ID>', api_secret_key: '<TC_SECRET_KEY>'",
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
