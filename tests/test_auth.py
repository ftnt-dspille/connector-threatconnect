"""Authentication: the signature covers the full request target, the token uses TC-Token."""
import base64
import hashlib
import hmac

import pytest

from conftest import ACCESS_ID, ConnectorError, operations as ops


def test_hmac_signs_the_full_request_target():
    """ThreatConnect's documented canonical string is path+query:method:timestamp."""
    endpoint = '/api/v3/indicators?resultStart=0&resultLimit=1'
    headers = ops.build_hmac_header('access-1', 'secret-1', endpoint, 'GET', timestamp=1513703787)
    sig = base64.b64encode(hmac.new(b'secret-1', ('%s:GET:1513703787' % endpoint).encode(), hashlib.sha256).digest()).decode()
    assert headers == {'Timestamp': '1513703787', 'Authorization': 'TC access-1:%s' % sig}


def test_signature_depends_on_the_query_string_and_the_method():
    sign = lambda ep, method='GET': ops.build_hmac_header('a', 'b', ep, method, timestamp=1)['Authorization']
    assert sign('/x?a=1') != sign('/x?a=2') != sign('/x')
    assert sign('/x') != sign('/x', 'PUT')


def test_auth_helper_signs_the_endpoint_verbatim():
    cfg = {'auth_type': ops.HMAC_AUTH, 'api_access_id': 'access-1', 'api_secret_key': 'secret-1'}  # pragma: allowlist secret
    headers = ops._build_auth_headers(cfg, '/api/v3/indicators?owner=Acme&resultLimit=1', 'GET')
    expected = ops.build_hmac_header('access-1', 'secret-1', '/api/v3/indicators?owner=Acme&resultLimit=1', 'GET',
                                     timestamp=int(headers['Timestamp']))
    assert headers == expected


def test_token_is_sent_with_the_tc_token_scheme():
    assert ops._build_auth_headers({'auth_type': ops.BEARER_AUTH, 'bearer_token': 'pat-xyz'}, '/x') == \
        {'Authorization': 'TC-Token pat-xyz'}


@pytest.mark.parametrize('cfg,needle', [
    ({'auth_type': ops.HMAC_AUTH}, 'Access ID'),
    ({'auth_type': ops.BEARER_AUTH}, 'Bearer Token'),
    ({'auth_type': 'Magic'}, 'Unsupported')])
def test_bad_credentials_fail_clearly(cfg, needle):
    with pytest.raises(ConnectorError, match=needle):
        ops._build_auth_headers(cfg, '/x')


def test_a_missing_server_url_is_a_clear_error():
    with pytest.raises(ConnectorError, match='Server URL'):
        ops.get_config_data({})


def test_the_mock_accepts_both_schemes_and_rejects_a_wrong_secret(server, config, token_config):
    assert ops._check_health(config) is True
    assert ops._check_health(token_config) is True
    with pytest.raises(ConnectorError, match='HTTP 401'):
        ops._check_health(dict(config, api_secret_key='wrong'))  # pragma: allowlist secret


def test_a_signature_over_the_path_alone_is_rejected(server, config):
    """The 2.1.0 regression: sign without the query string and every filtered call is a 401."""
    import requests
    path, full = '/api/v3/indicators', '/api/v3/indicators?resultLimit=1'
    headers = ops.build_hmac_header(ACCESS_ID, config['api_secret_key'], path, 'GET')
    assert requests.get(server.url + full, headers=headers).status_code == 401
    headers = ops.build_hmac_header(ACCESS_ID, config['api_secret_key'], full, 'GET')
    assert requests.get(server.url + full, headers=headers).status_code == 200
