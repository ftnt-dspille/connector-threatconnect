"""Test harness: stub the FortiSOAR connector SDK, load the connector as a package, and run
the mock ThreatConnect server (tests/mock_threatconnect.py) on a local port.

The mock VERIFIES the HMAC signature (path + query string + method + timestamp) and the
TC-Token scheme, so a signing regression fails here instead of at a customer.
"""
import importlib
import sys
import threading
import types
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONNECTOR_DIR = ROOT / 'threatconnect'
sys.path.insert(0, str(Path(__file__).parent))


def _install_sdk_stub():
    """connectors.core.connector as the appliance provides it."""
    class ConnectorError(Exception):
        pass

    class Connector(object):
        pass

    class _Logger(object):
        def __getattr__(self, name):
            return lambda *a, **k: None

    module = types.ModuleType('connectors.core.connector')
    module.ConnectorError = ConnectorError
    module.Connector = Connector
    module.get_logger = lambda name: _Logger()
    for name in ('connectors', 'connectors.core'):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules['connectors.core.connector'] = module


_install_sdk_stub()
package = types.ModuleType('threatconnect')
package.__path__ = [str(CONNECTOR_DIR)]
sys.modules['threatconnect'] = package
operations = importlib.import_module('threatconnect.operations')
connector_module = importlib.import_module('threatconnect.connector')
ConnectorError = sys.modules['connectors.core.connector'].ConnectorError

ACCESS_ID = 'test-access-id'
SECRET_KEY = 'test-secret-key'  # pragma: allowlist secret
PAT = 'test-pat'


def make_rows(count=60):
    """Deterministic indicators: a mix of types and owners, modified over the last 72 hours."""
    now = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
    rows = []
    for i in range(count):
        kind = ['Address', 'Host', 'URL', 'EmailAddress', 'File'][i % 5]
        summary = {'Address': '203.0.113.%d' % (i % 250 + 1), 'Host': 'host-%04d.example.com' % i,
                   'URL': 'https://example.com/p/%04d' % i, 'EmailAddress': 'user-%04d@example.com' % i,
                   'File': ('%064x' % (i + 1))}[kind]
        stamp = (now - timedelta(hours=i)).strftime('%Y-%m-%dT%H:%M:%SZ')
        rows.append({'id': 1000 + i, 'type': kind, 'summary': summary, 'rating': 3.0, 'confidence': 50 + i % 40,
                     'ownerName': 'FortiLab Org', 'dateAdded': stamp, 'lastModified': stamp,
                     'threatAssess': {'rating': 3.0, 'confidence': 50, 'count': 1},
                     'description': 'Indicator %d' % i, 'tags': ['Phishing']})
    return rows


@pytest.fixture
def server():
    """A fresh mock server per test; yields its base URL and its dataset."""
    import mock_threatconnect as mock
    mock.Handler.ds = mock.Dataset(make_rows())
    mock.Handler.access_id = ACCESS_ID
    mock.Handler.secret_key = SECRET_KEY
    mock.Handler.pat = PAT
    mock.Handler.no_auth = False
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), mock.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield types.SimpleNamespace(url='http://127.0.0.1:%d' % httpd.server_address[1], ds=mock.Handler.ds, mock=mock)
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def config(server):
    return {'api_base_url': server.url, 'auth_type': operations.HMAC_AUTH, 'api_access_id': ACCESS_ID,
            'api_secret_key': SECRET_KEY, 'api_default_org': 'FortiLab Org', 'verify': False}


@pytest.fixture
def token_config(server):
    return {'api_base_url': server.url, 'auth_type': operations.BEARER_AUTH, 'bearer_token': PAT,
            'api_default_org': 'FortiLab Org', 'verify': False}


@pytest.fixture
def run(config):
    """run('op', **params) through Connector.execute, as the platform does."""
    instance = connector_module.ThreatConnect()
    return lambda op, **params: instance.execute(config, op, params)
