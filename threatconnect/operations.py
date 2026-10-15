""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import hmac
import json
import re
import time
import urllib.parse
from base64 import b64encode
from hashlib import sha256

import arrow
import requests
from connectors.core.connector import get_logger, ConnectorError

from .constants import *

logger = get_logger('threatconnect')

HMAC_AUTH = 'HMAC (Access ID + Secret Key)'
BEARER_AUTH = 'Bearer Token'
REQUEST_TIMEOUT = 60
RETRY_STATUSES = (429, 502, 503, 504)
MAX_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# Configuration and authentication
# ---------------------------------------------------------------------------

def get_config_data(config):
    base_url = (config.get('api_base_url') or '').strip().strip('/')
    if not base_url:
        raise ConnectorError('Server URL is required.')
    if base_url[:7] != 'http://' and base_url[:8] != 'https://':
        base_url = 'https://{}'.format(str(base_url))
    access_id = config.get('api_access_id', None)
    secret_key = config.get('api_secret_key', None)
    default_org = config.get('api_default_org', None)
    verify_ssl = config.get('verify', None)
    return base_url, access_id, secret_key, default_org, verify_ssl


def _auth_type(config):
    return (config.get('auth_type') or HMAC_AUTH).strip()


def build_hmac_header(access_id, secret_key, endpoint, method='GET', timestamp=None):
    """Sign the request target exactly as it goes on the wire.

    ThreatConnect's documented HMAC scheme signs ``path+query:method:timestamp``
    (docs.threatconnect.com, REST API Quick Start > Access ID and Secret Key:
    the docs' own example includes the query string -- "...?Owner=Common%20Community:GET:1513703787").
    The signature must therefore be computed over the endpoint string AFTER the
    query parameters are built and BEFORE the request is sent -- signing
    anything else (e.g. the path only) is a guaranteed 401 on every filtered
    call. ``timestamp`` is injectable for deterministic tests only; the live
    path always stamps "now".
    """
    curr_timestamp = timestamp if timestamp is not None else arrow.now().int_timestamp
    headers = {
        'Timestamp': '{0}'.format(curr_timestamp)
    }
    secret = bytes(secret_key, 'utf-8')
    message = bytes(f'{endpoint}:{method}:{curr_timestamp}', 'utf-8')
    signature = b64encode(hmac.new(secret, message, digestmod=sha256).digest()).decode()
    auth = f'TC {access_id}:{signature}'
    headers.update({'Authorization': auth})
    return headers


def _build_auth_headers(config, endpoint, method='GET'):
    """Build auth headers for ``endpoint`` (the full request target, query included)."""
    auth_type = _auth_type(config)
    if auth_type == HMAC_AUTH:
        access_id = config.get('api_access_id') or ''
        secret_key = config.get('api_secret_key') or ''
        if not access_id or not secret_key:
            raise ConnectorError("Access ID and Secret Key are required for HMAC authentication.")
        # ThreatConnect signs the request target WITH the query string, so the
        # endpoint string is signed verbatim -- callers must pass it after the
        # query params are assembled, which every caller here does.
        return build_hmac_header(access_id, secret_key, endpoint, method)
    if auth_type == BEARER_AUTH:
        token = config.get('bearer_token') or ''
        if not token:
            raise ConnectorError("Bearer Token is required for Bearer authentication.")
        # ThreatConnect's documented token scheme -- for API tokens AND Personal
        # Access Tokens -- is ``Authorization: TC-Token <token>`` (REST API Quick
        # Start > API Token). ``Bearer`` appears nowhere in TC's docs and is
        # rejected by the platform.
        return {'Authorization': 'TC-Token {0}'.format(token)}
    raise ConnectorError('Unsupported Authentication Type: {0}'.format(auth_type))


TAXII_MEDIA = 'application/taxii+json;version=2.1'
TAXII_BASE_PATH = '/api/services/taxii/v2/taxii'


def _taxii_headers(config):
    """HTTP Basic for the TAXII user, as ThreatConnect's TAXII 2.1 server requires.

    The TAXII Server Service App authenticates a dedicated TAXII user with Basic auth and
    wants ``Accept: application/taxii+json;version=2.1``; the v3 HMAC and token schemes are
    not accepted there."""
    user = config.get('taxii_username') or ''
    password = config.get('taxii_password') or ''
    if not user or not password:
        raise ConnectorError('TAXII Username and TAXII Password are required for the STIX/TAXII actions.')
    token = b64encode('{0}:{1}'.format(user, password).encode('utf-8')).decode()
    return {'Authorization': 'Basic {0}'.format(token), 'Accept': TAXII_MEDIA}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def build_pagination_query(params):
    lst = ['resultStart', 'resultLimit']
    q_str = ''
    for param_key in lst:
        param_val = params.get(param_key)
        if param_val is not None and param_val != '' and param_val != {} and param_val != []:
            if q_str:
                q_str += f'&{param_key}={param_val}'
            else:
                q_str += f'{param_key}={param_val}'
    return q_str


def _failure_text(response):
    """The platform's own message when it sent one, else the generic text for the status code."""
    try:
        body = response.json()
        message = body.get('message') or body.get('description') or body.get('title')
    except (ValueError, AttributeError):
        message = None
    return message or error_msg.get(response.status_code) or response.text[:300]


def make_request(base_url, access_id, secret_key, verify_ssl, endpoint, method='GET', config=None, body=None,
                 taxii=False):
    """Send one request to ``base_url + endpoint`` and return the parsed reply.

    ``taxii`` sends the TAXII user's Basic credentials and the TAXII media type instead of a v3
    signature or token. ``body`` (a dict) is sent as JSON. Reads are retried on 429 and 5xx gateway
    errors; writes are sent once, so a retry can never create or delete twice.
    """
    try:
        # Backward-compatible: if a config dict is supplied, route through the auth-type
        # selector (HMAC or Bearer). Existing callers that pass only access_id/secret_key
        # still work via the HMAC path below.
        url = base_url + endpoint
        attempts = MAX_ATTEMPTS if method == 'GET' else 1
        for attempt in range(1, attempts + 1):
            # A fresh signature each attempt: the timestamp is part of what is signed.
            if taxii:
                headers = _taxii_headers(config)
            elif config is not None:
                headers = _build_auth_headers(config, endpoint, method)
            else:
                headers = build_hmac_header(access_id, secret_key, endpoint, method)
            data = None
            if body is not None:
                headers['Content-Type'] = 'application/json'
                data = json.dumps(body)
            logger.info('Requested url:{0}'.format(url))
            response = requests.request(method=method, url=url, headers=headers, data=data,
                                        verify=verify_ssl, timeout=REQUEST_TIMEOUT)
            if response.status_code in RETRY_STATUSES and attempt < attempts:
                try:
                    pause = min(float(response.headers.get('Retry-After', attempt)), 10)
                except ValueError:
                    pause = attempt
                time.sleep(pause)
                continue
            break
        if response.ok:
            if 'json' in (response.headers.get('Content-Type') or '').lower():
                result = response.json()
                if (result.get('status') or 'success').lower() in ('failure', 'error'):
                    raise ConnectorError('HTTP {0} {1} {2}: {3}'.format(
                        response.status_code, method, endpoint.split('?')[0], _failure_text(response)))
                return result
            return response.content.decode() if isinstance(response.content, bytes) else response.content
        logger.error("Error: {0}:{1}".format(response.status_code, response.text))
        raise ConnectorError('HTTP {0} {1} {2}: {3}'.format(
            response.status_code, method, endpoint.split('?')[0], _failure_text(response)))
    except ConnectorError:
        raise
    except requests.exceptions.SSLError as e:
        raise ConnectorError('{0}'.format(e))
    except requests.exceptions.ConnectionError as e:
        raise ConnectorError('{0}'.format(e))
    except Exception as e:
        raise ConnectorError('{0}'.format(e))


def _call(config, endpoint, method='GET', body=None):
    base_url, access_id, secret_key, default_org, verify_ssl = get_config_data(config)
    return make_request(base_url, access_id, secret_key, verify_ssl, endpoint, method, config=config, body=body)


def _taxii_root(config):
    """The TAXII API root path: the configured base path (App v2.0 by default) plus /tc_taxii."""
    base = (config.get('taxii_base_path') or TAXII_BASE_PATH).strip().rstrip('/')
    if not base.startswith('/'):
        base = '/' + base
    return base + '/tc_taxii'


def _taxii_call(config, path):
    base_url, access_id, secret_key, default_org, verify_ssl = get_config_data(config)
    return make_request(base_url, access_id, secret_key, verify_ssl, _taxii_root(config) + path,
                        config=config, taxii=True)


def _blank(value):
    return value is None or (isinstance(value, str) and not value.strip()) or value == [] or value == {}


def _owner(config, params):
    """The owner to act on: the action's own, else the configuration's default organization."""
    owner = params.get('owner')
    if _blank(owner):
        owner = config.get('api_default_org')
    return None if _blank(owner) else str(owner).strip()


def _query(pairs):
    """Build ``?a=b&c=d`` from (key, value) pairs, skipping blanks and percent-encoding values."""
    parts = ['{0}={1}'.format(key, urllib.parse.quote(str(value), safe=''))
             for key, value in pairs if not _blank(value)]
    return '?' + '&'.join(parts) if parts else ''


def _csv(value):
    """A comma-separated string or a list, as a list of trimmed non-empty strings."""
    if _blank(value):
        return []
    if isinstance(value, str):
        value = value.split(',')
    return [str(item).strip() for item in value if str(item).strip()]


def _tql_value(value):
    """Escape a value for a double-quoted TQL string."""
    return str(value).replace('\\', '\\\\').replace('"', '\\"')


def _object(value, name):
    """A JSON object from a dict or a JSON string; blank means none."""
    if _blank(value):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise ConnectorError('{0} must be valid JSON.'.format(name))
    if not isinstance(value, dict):
        raise ConnectorError('{0} must be a JSON object.'.format(name))
    return value


def _ident(indicator):
    """An indicator id or summary, made safe for a URL path."""
    if _blank(indicator):
        raise ConnectorError('Indicator is required.')
    return urllib.parse.quote(str(indicator).strip(), safe='')


# ---------------------------------------------------------------------------
# Reputation lookups
# ---------------------------------------------------------------------------

def get_single_indicator(config, params):
    indicator_value = params.get('indicator')
    include_additional = params.get('includeAdditional')
    include_params = params.get('include_params') or []
    group_attributes = params.get('attributes', False)
    # Encoded once, here: a value holding / ? # or & must stay one path segment and never
    # reach the query string.
    endpoint = '/api/v3/indicators/{0}'.format(_ident(indicator_value))
    owner = _owner(config, params)
    # Percent-encode the owner name the way TC's own docs example does
    # (``?Owner=Common%20Community``). quote() also handles the characters
    # that .replace(" ", "%20") silently corrupted (&, =, #, non-ASCII).
    query_str = _query([('owner', owner)])
    if include_additional and include_params:
        include_fields = [PARAM_MAPPING.get(i) for i in include_params]
        if group_attributes:
            include_fields[-1] = include_fields[-1] + '.attributes'
        fields_str = '&'.join(f'fields={i}' for i in include_fields)
        query_str += ('&' if query_str else '?') + fields_str
    return _call(config, endpoint + query_str)


def hunt_ip(config, params):
    return get_single_indicator(config, params)


def hunt_file(config, params):
    return get_single_indicator(config, params)


def hunt_email(config, params):
    return get_single_indicator(config, params)


def hunt_url(config, params):
    return get_single_indicator(config, params)


def hunt_host(config, params):
    return get_single_indicator(config, params)


def _check_health(config):
    endpoint = f'/api/v3/indicators?resultStart=0&resultLimit=1'
    try:
        result = _call(config, endpoint)
        if result:
            return True
    except Exception as err:
        logger.exception("Error connecting to ThreatConnect. {}".format(str(err)))
        raise ConnectorError(err)


def list_indicator(config, params):
    include_additional = params.get('includeAdditional', True)
    endpoint = f'/api/v3/indicators'
    q_str = build_pagination_query(params)
    if include_additional:
        include_fields = ['tags', 'threatAssess', 'associatedGroups.attributes']
        fields_list = [f'fields={i}' for i in include_fields]
        fields_str = '&'.join(fields_list)
        endpoint += '?{fields_str}'.format(fields_str=fields_str) + ('&{q_str}'.format(q_str=q_str) if q_str else q_str)
    else:
        endpoint += '?{q_str}'.format(q_str=q_str) if q_str else q_str
    return _call(config, endpoint)


# ---------------------------------------------------------------------------
# Generic REST call
# ---------------------------------------------------------------------------

def invoke_api(config, params):
    """Call any ThreatConnect REST endpoint with the configuration's credentials.

    ``endpoint`` is a path on the configured server (``/api/v3/...``). A full URL
    or a ``..`` segment is refused so the signature or token can never be sent to
    another host. ``method`` defaults to GET; ``request_body`` is a JSON object for
    POST and PUT.
    """
    endpoint = (params.get('endpoint') or '').strip()
    if not endpoint:
        raise ConnectorError('Endpoint is required.')
    parsed = urllib.parse.urlparse(endpoint)
    decoded = endpoint.split('?')[0]
    for _ in range(3):
        decoded = urllib.parse.unquote(decoded)
    if parsed.scheme or parsed.netloc or '..' in decoded.split('/') or '\\' in decoded:
        raise ConnectorError('Endpoint must be a path on the configured server, '
                             'e.g. /api/v3/indicators - not a full URL.')
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint
    method = (params.get('method') or 'GET').upper()
    if method not in ('GET', 'POST', 'PUT', 'DELETE'):
        raise ConnectorError('Method must be GET, POST, PUT or DELETE.')
    body = _object(params.get('request_body'), 'Request Body') or None
    return _call(config, endpoint, method, body)


# ---------------------------------------------------------------------------
# Bulk pull (used by ingestion)
# ---------------------------------------------------------------------------

def fetch_indicators(config, params):
    """Bulk-pull indicators from /api/v3/indicators with optional filters and full pagination.

    Used by scheduled data ingestion and available on-demand. The TC v3 API supports
    a TQL filter via ?tql=, plus paging via resultStart/resultLimit (cap 1000).
    """
    base_url, access_id, secret_key, default_org, verify_ssl = get_config_data(config)
    indicator_type = (params.get('indicator_type') or 'Any').strip()
    owner = (params.get('owner') or default_org or '').strip()
    modified_since = (params.get('modified_since') or '').strip()
    try:
        page_size = int(params.get('page_size') or 500)
    except (TypeError, ValueError):
        page_size = 500
    page_size = max(1, min(page_size, 1000))
    limit_raw = params.get('limit')
    try:
        total_limit = int(limit_raw) if limit_raw not in (None, '', 0, '0') else None
    except (TypeError, ValueError):
        total_limit = None

    tql_clauses = []
    if indicator_type and indicator_type != 'Any':
        tql_clauses.append('typeName = "{0}"'.format(_tql_value(indicator_type)))
    if owner:
        tql_clauses.append('ownerName = "{0}"'.format(_tql_value(owner)))
    if modified_since:
        tql_clauses.append('lastModified >= "{0}"'.format(_tql_value(modified_since)))
    tql = ' AND '.join(tql_clauses)

    fields = ['threatAssess', 'tags']
    fields_qs = '&'.join('fields={0}'.format(f) for f in fields)

    indicators = []
    result_start = 0
    truncated = False
    while True:
        endpoint = '/api/v3/indicators?{0}&resultStart={1}&resultLimit={2}'.format(
            fields_qs, result_start, page_size)
        if tql:
            endpoint += '&tql={0}'.format(urllib.parse.quote(tql, safe=''))
        # The TC v3 indicators endpoint returns at most page_size items; loop until empty.
        page = make_request(base_url, access_id, secret_key, verify_ssl, endpoint, config=config)
        page_data = (page or {}).get('data') or []
        if not page_data:
            break
        for ind in page_data:
            indicators.append(ind)
            if total_limit and len(indicators) >= total_limit:
                truncated = True
                break
        if truncated:
            break
        if len(page_data) < page_size:
            break
        result_start += page_size

    return {
        'indicators': indicators,
        'count': len(indicators),
        'truncated': truncated,
    }


# ---------------------------------------------------------------------------
# STIX / TAXII 2.1 (ThreatConnect TAXII Server Service App)
# ---------------------------------------------------------------------------

# STIX cyber-observable -> the ThreatConnect indicator type the ingestion playbooks key on.
STIX_TYPES = {'ipv4-addr': 'Address', 'ipv6-addr': 'Address', 'domain-name': 'Host', 'url': 'URL',
              'email-addr': 'EmailAddress', 'file': 'File'}
STIX_HASH_ORDER = ('MD5', 'SHA-1', 'SHA-256')
TLP_MARKING_IDS = {
    'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9': 'White',
    'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da': 'Green',
    'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82': 'Amber',
    'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed': 'Red',
}
_COMPARISON = r"([a-z0-9-]+):([^\s=]+)\s*=\s*'((?:[^'\\]|\\.)*)'"
MAX_TAXII_PAGES = 1000


def parse_stix_pattern(pattern):
    """(object type, property, value) for every ``obj:prop = 'value'`` comparison in a STIX pattern."""
    return [(obj, prop, re.sub(r'\\(.)', r'\1', value)) for obj, prop, value in re.findall(_COMPARISON, pattern or '')]


def _stix_value(pattern):
    """(ThreatConnect type, summary) for a pattern, or None when it holds nothing the feed ingests.

    A file pattern may carry several hashes; they become ``md5 : sha1 : sha256`` in the order
    the v3 API uses, which the ingestion playbooks already split on."""
    comparisons = parse_stix_pattern(pattern)
    kinds = {STIX_TYPES.get(obj) for obj, _, _ in comparisons}
    if len(kinds) != 1 or None in kinds:
        return None
    kind = kinds.pop()
    if kind == 'File':
        hashes = {}
        for _, prop, value in comparisons:
            m = re.match(r"hashes\.'?([A-Za-z0-9-]+)'?$", prop)
            if m:
                hashes[m.group(1).upper().replace('SHA1', 'SHA-1').replace('SHA256', 'SHA-256')] = value
        parts = [hashes[h] for h in STIX_HASH_ORDER if h in hashes]
        return ('File', ' : '.join(parts)) if parts else None
    return kind, comparisons[0][2]


def _tlp_for(indicator, markings):
    """The TLP name (Red/Amber/Green/White) an indicator's marking references carry, else None."""
    for ref in indicator.get('object_marking_refs') or []:
        marking = markings.get(ref) or {}
        name = (marking.get('definition') or {}).get('tlp') or (TLP_MARKING_IDS.get(ref) or '')
        if name and str(name).capitalize() in ('Red', 'Amber', 'Green', 'White'):
            return str(name).capitalize()
    return None


def stix_to_indicator(obj, markings):
    """One STIX ``indicator`` as the record shape the v3 bulk pull returns, or None to skip it.

    Keeping the v3 shape (id, type, summary, rating, confidence, ownerName, dateAdded,
    lastModified, description, tags) means the same ingestion mapping serves both feeds."""
    if obj.get('type') != 'indicator' or obj.get('pattern_type', 'stix') != 'stix':
        return None
    found = _stix_value(obj.get('pattern'))
    if found is None:
        return None
    kind, summary = found
    tc_id = obj.get('x_threatconnect_id')
    record = {
        'id': str(tc_id) if tc_id not in (None, '') else obj.get('id'),
        'stix_id': obj.get('id'),
        'type': kind,
        'summary': summary,
        'rating': float(obj.get('x_threat_rating') or 0),
        'confidence': int(obj.get('confidence') or 0),
        'ownerName': obj.get('x_threatconnect_owner'),
        'dateAdded': obj.get('created') or obj.get('valid_from'),
        'lastModified': obj.get('modified') or obj.get('created'),
        'description': obj.get('description') or obj.get('name') or '',
        'tags': list(obj.get('labels') or []),
        'tlp': _tlp_for(obj, markings),
        'threatConnectType': obj.get('x_threatconnect_type'),
    }
    return record


def _since(value):
    """A UTC arrow for a pull cursor; blank, 0 and unparseable all mean no cursor."""
    if _blank(value) or str(value).strip() in ('0', '0.0'):
        return None
    try:
        return arrow.get(str(value).strip())
    except Exception:
        try:
            return arrow.get(float(value))
        except Exception:
            raise ConnectorError('Modified Since must be an ISO 8601 datetime, got {0}.'.format(value))


def taxii_list_collections(config, params):
    """The TAXII collections this user can read: one per ThreatConnect owner (GET .../collections)."""
    return _taxii_call(config, '/collections')


def get_collection_options(config, params):
    """Collection dropdown: the title (owner name) of every readable collection."""
    collections = (taxii_list_collections(config, params) or {}).get('collections') or []
    return sorted({c.get('title') for c in collections if c.get('title')}, key=str.lower)


def _collection_path(collection):
    if _blank(collection):
        raise ConnectorError('Collection is required.')
    return '/collections/{0}'.format(urllib.parse.quote(str(collection).strip(), safe=''))


def taxii_get_objects(config, params):
    """One page of a collection's STIX objects, as the server sent it (GET .../objects).

    Returns the TAXII envelope: ``objects``, ``more`` and ``next``. Pass ``next`` back to read on."""
    query = _query([('limit', params.get('limit')), ('next', params.get('next')),
                    ('added_after', params.get('added_after'))])
    result = _taxii_call(config, _collection_path(params.get('collection')) + '/objects' + query)
    # the spec omits "objects" when there is nothing to return
    result.setdefault('objects', [])
    return result


def _fetch_collection(config, collection, added_after, page_size, markings):
    """Every indicator object in one collection, following ``more``/``next`` to the end."""
    objects, cursor = [], None
    for _ in range(MAX_TAXII_PAGES):
        query = _query([('limit', page_size), ('next', cursor), ('added_after', added_after)])
        page = _taxii_call(config, _collection_path(collection) + '/objects' + query) or {}
        for obj in page.get('objects') or []:
            if obj.get('type') == 'marking-definition':
                markings[obj.get('id')] = obj
            else:
                objects.append(obj)
        cursor = page.get('next')
        if not page.get('more') or _blank(cursor):
            return objects
    raise ConnectorError('Stopped after {0} pages of collection {1}.'.format(MAX_TAXII_PAGES, collection))


def fetch_stix_indicators(config, params):
    """Bulk-pull indicators from ThreatConnect's TAXII 2.1 server and return them in the v3 record shape.

    Used by scheduled STIX ingestion. ``owner`` names one collection (an owner name or a collection
    id); blank means the Default Organization, and without one, every readable collection.

    ``added_after`` is sent so a server that implements it can skip old objects, but ThreatConnect
    does not document it, so the cursor is ALSO applied here to each object's ``modified`` time:
    a server that ignores the parameter costs bandwidth, never duplicates or a missed update.
    Patterns the feed cannot ingest (ASN, mutex, registry key...) are counted in ``skipped``."""
    wanted_type = (params.get('indicator_type') or 'Any').strip()
    owner = (params.get('owner') or config.get('api_default_org') or '').strip()
    cursor = _since(params.get('modified_since'))
    try:
        page_size = max(1, min(int(params.get('page_size') or 500), 1000))
    except (TypeError, ValueError):
        page_size = 500
    try:
        total_limit = int(params.get('limit') or 0) or None
    except (TypeError, ValueError):
        total_limit = None

    if owner:
        collections = [owner]
    else:
        collections = [c.get('id') for c in (taxii_list_collections(config, {}) or {}).get('collections') or []
                       if c.get('can_read', True) and c.get('id')]
    # added_after is exclusive in TAXII and the cursor is inclusive here, so ask for one millisecond earlier.
    added_after = (cursor.shift(microseconds=-1000).to('utc').strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                   if cursor else None)

    indicators, skipped, truncated, seen = [], 0, False, set()
    markings = {}
    for collection in collections:
        for obj in _fetch_collection(config, collection, added_after, page_size, markings):
            record = stix_to_indicator(obj, markings)
            if record is None:
                skipped += 1
                continue
            if wanted_type != 'Any' and record['type'] != wanted_type:
                continue
            if cursor and record['lastModified'] and arrow.get(record['lastModified']) < cursor:
                continue
            if record['stix_id'] in seen:
                continue
            seen.add(record['stix_id'])
            indicators.append(record)
            if total_limit and len(indicators) >= total_limit:
                truncated = True
                break
        if truncated:
            break
    return {'indicators': indicators, 'count': len(indicators), 'truncated': truncated,
            'skipped': skipped, 'collections': len(collections)}


# ---------------------------------------------------------------------------
# Indicators: read, create, update, delete
# ---------------------------------------------------------------------------

def get_indicator(config, params):
    """Retrieve one indicator by id or summary (GET /v3/indicators/{id or summary})."""
    fields = [('fields', f) for f in _csv(params.get('fields'))]
    return _call(config, '/api/v3/indicators/{0}{1}'.format(
        _ident(params.get('indicator')), _query([('owner', _owner(config, params))] + fields)))


def _file_hash_field(value):
    """The v3 field name for a file hash, from its length: md5 32, sha1 40, sha256 64."""
    field = {32: 'md5', 40: 'sha1', 64: 'sha256'}.get(len(value))
    if field is None:
        raise ConnectorError('A file hash must be 32 (MD5), 40 (SHA1) or 64 (SHA256) characters.')
    return field


def _indicator_body(indicator_type, value):
    if indicator_type not in INDICATOR_VALUE_FIELDS:
        raise ConnectorError('Indicator type must be one of: {0}.'.format(', '.join(sorted(INDICATOR_VALUE_FIELDS))))
    if _blank(value):
        raise ConnectorError('Indicator value is required.')
    value = str(value).strip()
    field = _file_hash_field(value) if indicator_type == 'File' else INDICATOR_VALUE_FIELDS[indicator_type]
    return {'type': indicator_type, field: value}


def _metadata(body, params):
    """Add the optional rating, confidence, tags, labels and description to a create or update body."""
    for name in ('rating', 'confidence'):
        if not _blank(params.get(name)):
            body[name] = float(params[name]) if name == 'rating' else int(params[name])
    tags = _csv(params.get('tags'))
    if tags:
        body['tags'] = {'data': [{'name': t} for t in tags]}
        if params.get('tag_mode'):
            body['tags']['mode'] = MODES[params['tag_mode']]
    labels = _csv(params.get('security_labels'))
    if labels:
        body['securityLabels'] = {'data': [{'name': l} for l in labels]}
        if params.get('label_mode'):
            body['securityLabels']['mode'] = MODES[params['label_mode']]
    if not _blank(params.get('description')):
        body['attributes'] = {'data': [{'type': 'Description', 'value': str(params['description']), 'default': True}]}
    body.update(_object(params.get('other_fields'), 'Other Fields'))
    return body


def create_indicator(config, params):
    """Create an indicator (POST /v3/indicators). An existing one in the same owner is updated."""
    body = _metadata(_indicator_body(params.get('indicator_type'), params.get('indicator')), params)
    return _call(config, '/api/v3/indicators' + _query([('owner', _owner(config, params))]), 'POST', body)


def update_indicator(config, params):
    """Change an indicator's rating, confidence, tags, security labels or description (PUT)."""
    body = _metadata({}, params)
    if not body:
        raise ConnectorError('Nothing to update: set at least one field.')
    return _call(config, '/api/v3/indicators/{0}{1}'.format(
        _ident(params.get('indicator')), _query([('owner', _owner(config, params))])), 'PUT', body)


def delete_indicator(config, params):
    return _call(config, '/api/v3/indicators/{0}{1}'.format(
        _ident(params.get('indicator')), _query([('owner', _owner(config, params))])), 'DELETE')


def mark_false_positive(config, params):
    """Flag an indicator as a false positive (PUT ?fields=falsePositives)."""
    return _call(config, '/api/v3/indicators/{0}{1}'.format(
        _ident(params.get('indicator')),
        _query([('owner', _owner(config, params)), ('fields', 'falsePositives')])), 'PUT',
        {'falsePositiveFlag': True})


def add_observation(config, params):
    """Record that the indicator was seen (PUT ?fields=observations)."""
    count = params.get('observations')
    count = 1 if _blank(count) else int(count)
    if count < 1:
        raise ConnectorError('Observations must be at least 1.')
    return _call(config, '/api/v3/indicators/{0}{1}'.format(
        _ident(params.get('indicator')),
        _query([('owner', _owner(config, params)), ('fields', 'observations')])), 'PUT',
        {'observations': count})


def list_deleted_indicators(config, params):
    """Indicators deleted since a time, to keep a mirror in step (GET /v3/indicators/deleted)."""
    indicator_type = params.get('indicator_type')
    if indicator_type == 'Any':
        indicator_type = None
    return _call(config, '/api/v3/indicators/deleted' + _query([
        ('owner', _owner(config, params)), ('type', indicator_type), ('deletedSince', params.get('deleted_since'))]))


# ---------------------------------------------------------------------------
# Owners, groups, tags
# ---------------------------------------------------------------------------

def list_owners(config, params):
    return _call(config, '/api/v3/security/owners')


def get_owner_options(config, params):
    """Owner dropdown: the name of every owner the credentials can see.

    The step editor draws a dropdown from a plain list of strings (a {title, value}
    object shows as "[object Object]"), and an owner is addressed by its name, which
    ThreatConnect keeps unique, so the names are the options and need no resolving."""
    owners = (_call(config, '/api/v3/security/owners') or {}).get('data') or []
    names = {o.get('name') for o in owners if o.get('name')}
    return sorted(names, key=str.lower)


def list_groups(config, params):
    """Groups (adversaries, incidents, reports...), optionally by type, name or a TQL filter."""
    clauses = []
    if not _blank(params.get('group_type')) and params['group_type'] != 'Any':
        clauses.append('typeName = "{0}"'.format(_tql_value(params['group_type'])))
    if not _blank(params.get('name')):
        clauses.append('name = "{0}"'.format(_tql_value(params['name'])))
    if not _blank(params.get('tql')):
        clauses.append(str(params['tql']).strip())
    pairs = [('owner', _owner(config, params)), ('tql', ' AND '.join(clauses)),
             ('resultStart', params.get('resultStart')), ('resultLimit', params.get('resultLimit'))]
    return _call(config, '/api/v3/groups' + _query(pairs))


def get_group(config, params):
    if _blank(params.get('group_id')):
        raise ConnectorError('Group ID is required.')
    return _call(config, '/api/v3/groups/{0}{1}'.format(
        urllib.parse.quote(str(params['group_id']).strip(), safe=''), _query([('owner', _owner(config, params))])))


def list_tags(config, params):
    return _call(config, '/api/v3/tags' + _query([
        ('owner', _owner(config, params)), ('resultStart', params.get('resultStart')),
        ('resultLimit', params.get('resultLimit'))]))


operations = {
    'hunt_ip': hunt_ip,
    'hunt_file': hunt_file,
    'hunt_email': hunt_email,
    'hunt_url': hunt_url,
    'hunt_host': hunt_host,
    'list_indicator': list_indicator,
    'invoke_api': invoke_api,
    'fetch_indicators': fetch_indicators,
    'get_indicator': get_indicator,
    'create_indicator': create_indicator,
    'update_indicator': update_indicator,
    'delete_indicator': delete_indicator,
    'mark_false_positive': mark_false_positive,
    'add_observation': add_observation,
    'list_deleted_indicators': list_deleted_indicators,
    'list_owners': list_owners,
    'list_groups': list_groups,
    'get_group': get_group,
    'list_tags': list_tags,
    'get_owner_options': get_owner_options,
    'taxii_list_collections': taxii_list_collections,
    'taxii_get_objects': taxii_get_objects,
    'fetch_stix_indicators': fetch_stix_indicators,
    'get_collection_options': get_collection_options,
}
