"""Every operation, end to end against the mock server (real HTTP, real signatures)."""
import pytest

from conftest import ConnectorError, operations as ops


# -- lookups ---------------------------------------------------------------

@pytest.mark.parametrize('op,kind', [('hunt_ip', 'Address'), ('hunt_file', 'File'), ('hunt_email', 'EmailAddress'),
                                     ('hunt_url', 'URL'), ('hunt_host', 'Host')])
def test_reputation_lookups_find_an_indicator_of_each_type(run, server, op, kind):
    value = next(r['summary'] for r in server.ds.rows if r['type'] == kind)
    assert run(op, indicator=value)['data']['summary'] == value


def test_a_lookup_with_no_owner_and_no_default_org_still_works(server, config):
    config['api_default_org'] = None
    value = server.ds.rows[0]['summary']
    from threatconnect.connector import ThreatConnect
    assert ThreatConnect().execute(config, 'hunt_ip', {'indicator': value})['data']['summary'] == value


def test_an_unknown_indicator_is_a_readable_error(run):
    with pytest.raises(ConnectorError, match='HTTP 404 GET /api/v3/indicators/198.51.100.99: .*not found'):
        run('hunt_ip', indicator='198.51.100.99')


def test_list_indicator_pages(run):
    assert len(run('list_indicator', includeAdditional=False, resultLimit=7)['data']) == 7


def test_get_indicator_by_summary_and_by_id(run, server):
    row = server.ds.rows[3]
    assert run('get_indicator', indicator=row['summary'])['data']['id'] == row['id']
    assert run('get_indicator', indicator=str(row['id']))['data']['summary'] == row['summary']


def test_get_indicator_url_value_is_encoded(run, server):
    url = next(r['summary'] for r in server.ds.rows if r['type'] == 'URL')
    assert run('get_indicator', indicator=url)['data']['summary'] == url


# -- bulk pull ---------------------------------------------------------------

def test_fetch_indicators_pulls_everything(run, server):
    result = run('fetch_indicators', page_size=25)
    assert result['count'] == len(server.ds.rows) and not result['truncated']


def test_fetch_indicators_filters_by_type_and_owner(run):
    result = run('fetch_indicators', indicator_type='Host', owner='FortiLab Org')
    assert result['count'] == 12 and {i['type'] for i in result['indicators']} == {'Host'}


def test_fetch_indicators_honours_the_limit_and_the_watermark(run):
    assert run('fetch_indicators', limit=5)['truncated'] is True
    assert run('fetch_indicators', modified_since='2099-01-01T00:00:00Z')['count'] == 0


def test_fetch_indicators_survives_a_quote_in_the_owner(run):
    assert run('fetch_indicators', owner='Acme "Intel"')['count'] == 0


# -- writes ------------------------------------------------------------------

def test_create_indicator_for_each_value_kind(run, server):
    cases = [('Address', '198.51.100.7'), ('Host', 'new.example.com'), ('URL', 'https://example.com/new'),
             ('EmailAddress', 'new@example.com'), ('File', 'a' * 32), ('File', 'b' * 40), ('File', 'c' * 64)]
    for kind, value in cases:
        assert run('create_indicator', indicator_type=kind, indicator=value)['data']['summary'] == value


def test_create_indicator_sends_rating_confidence_tags_labels_and_description(run, server):
    run('create_indicator', indicator_type='Address', indicator='198.51.100.8', rating='4.5', confidence=80,
        tags='Phishing, APT', security_labels='TLP:AMBER', description='seen in the wild')
    row = server.ds.find('198.51.100.8')
    assert (row['rating'], row['confidence'], row['tags'], row['securityLabels']) == \
        (4.5, 80, ['Phishing', 'APT'], ['TLP:AMBER'])


def test_create_indicator_twice_updates_rather_than_duplicating(run, server):
    for _ in range(2):
        run('create_indicator', indicator_type='Address', indicator='198.51.100.9')
    assert sum(1 for r in server.ds.rows if r['summary'] == '198.51.100.9') == 1


def test_create_indicator_validates_before_sending(run):
    with pytest.raises(ConnectorError, match='32 .MD5., 40'):
        run('create_indicator', indicator_type='File', indicator='abc')
    with pytest.raises(ConnectorError, match='type must be one of'):
        run('create_indicator', indicator_type='Nope', indicator='x')
    with pytest.raises(ConnectorError, match='value is required'):
        run('create_indicator', indicator_type='Address', indicator='  ')
    with pytest.raises(ConnectorError, match='valid JSON'):
        run('create_indicator', indicator_type='Address', indicator='198.51.100.1', other_fields='{nope')


def test_create_indicator_other_fields_merge_into_the_body(run, server):
    run('create_indicator', indicator_type='Host', indicator='merge.example.com', other_fields='{"rating": 2}')
    assert server.ds.find('merge.example.com')['rating'] == 2


def test_update_indicator_modes(run, server):
    value = server.ds.rows[0]['summary']
    run('update_indicator', indicator=value, tags='Botnet')
    assert server.ds.find(value)['tags'] == ['Phishing', 'Botnet']
    run('update_indicator', indicator=value, tags='Only', tag_mode='Replace')
    assert server.ds.find(value)['tags'] == ['Only']
    run('update_indicator', indicator=value, tags='Only', tag_mode='Remove')
    assert server.ds.find(value)['tags'] == []
    run('update_indicator', indicator=value, rating=1, confidence=10)
    row = server.ds.find(value)
    assert (row['rating'], row['confidence']) == (1.0, 10)


def test_update_indicator_needs_something_to_change(run, server):
    with pytest.raises(ConnectorError, match='Nothing to update'):
        run('update_indicator', indicator=server.ds.rows[0]['summary'])


def test_update_of_an_unknown_indicator_is_a_404(run):
    with pytest.raises(ConnectorError, match='HTTP 404 PUT'):
        run('update_indicator', indicator='198.51.100.250', rating=1)


def test_mark_false_positive_and_add_observation(run, server):
    value = server.ds.rows[1]['summary']
    run('mark_false_positive', indicator=value)
    run('add_observation', indicator=value, observations=3)
    run('add_observation', indicator=value)
    row = server.ds.find(value)
    assert row['falsePositiveFlag'] is True and row['observationCount'] == 4
    with pytest.raises(ConnectorError, match='at least 1'):
        run('add_observation', indicator=value, observations=0)


def test_delete_indicator_and_list_deleted(run, server):
    value = server.ds.rows[2]['summary']
    run('delete_indicator', indicator=value)
    assert server.ds.find(value) is None
    deleted = run('list_deleted_indicators', deleted_since='2020-01-01T00:00:00Z')
    assert [d['summary'] for d in deleted['data']] == [value]
    assert run('list_deleted_indicators', indicator_type='Host')['data'] == []
    assert run('list_deleted_indicators', indicator_type='Any')['count'] == 1


# -- owners, groups, tags ----------------------------------------------------------

def test_list_owners_and_the_dropdown(run):
    assert {o['name'] for o in run('list_owners')['data']} == {'FortiLab Org', 'Common Community', 'Lab Source'}
    options = run('get_owner_options')
    assert {'title': 'FortiLab Org (Organization)', 'value': 'FortiLab Org'} in options


def test_list_groups_filters(run):
    assert len(run('list_groups')['data']) == 3
    assert [g['name'] for g in run('list_groups', group_type='Incident')['data']] == ['Lab Incident 7']
    assert [g['type'] for g in run('list_groups', name='Lab Report Q3')['data']] == ['Report']
    assert len(run('list_groups', group_type='Any', tql='ownerName = "FortiLab Org"')['data']) == 2


def test_get_group(run):
    assert run('get_group', group_id=101)['data']['type'] == 'Adversary'
    with pytest.raises(ConnectorError, match='Group ID is required'):
        run('get_group')
    with pytest.raises(ConnectorError, match='HTTP 404'):
        run('get_group', group_id=999)


def test_list_tags(run):
    assert 'Phishing' in [t['name'] for t in run('list_tags')['data']]


# -- generic call ------------------------------------------------------------------

def test_invoke_api_get_post_put_delete(run, server):
    assert run('invoke_api', endpoint='/api/v3/security/owners')['count'] == 3
    created = run('invoke_api', endpoint='/api/v3/indicators', method='POST',
                  request_body='{"type": "Address", "ip": "198.51.100.77"}')
    assert created['data']['summary'] == '198.51.100.77'
    run('invoke_api', endpoint='/api/v3/indicators/198.51.100.77', method='PUT', request_body={'rating': 5})
    assert server.ds.find('198.51.100.77')['rating'] == 5
    run('invoke_api', endpoint='/api/v3/indicators/198.51.100.77', method='DELETE')
    assert server.ds.find('198.51.100.77') is None


@pytest.mark.parametrize('endpoint', [
    'https://evil.example.com/steal', '//evil.example.com/x', 'ftp://x/y', '/api/v3/../../etc',
    '/api/v3/%2e%2e/%2e%2e/etc', '/api/v3/%252e%252e/etc', '/api/v3/..%5cetc'])
def test_invoke_api_refuses_anything_that_could_send_credentials_elsewhere(run, endpoint):
    with pytest.raises(ConnectorError, match='path on the configured server'):
        run('invoke_api', endpoint=endpoint)


def test_invoke_api_validates_method_and_body(run):
    with pytest.raises(ConnectorError, match='Endpoint is required'):
        run('invoke_api')
    with pytest.raises(ConnectorError, match='Method must be'):
        run('invoke_api', endpoint='/api/v3/tags', method='PATCH')
    with pytest.raises(ConnectorError, match='JSON object'):
        run('invoke_api', endpoint='/api/v3/tags', method='POST', request_body='[1]')


def test_invoke_api_works_with_a_token(server, token_config):
    from threatconnect.connector import ThreatConnect
    assert ThreatConnect().execute(token_config, 'invoke_api', {'endpoint': '/api/v3/tags'})['status'] == 'Success'


# -- plumbing ---------------------------------------------------------------------

def test_an_unknown_operation_is_a_clear_error(run):
    with pytest.raises(ConnectorError, match='Unsupported operation: nope'):
        run('nope')


def test_reads_are_retried_and_writes_are_not(monkeypatch, server, config):
    calls = []

    class Reply(object):
        def __init__(self, status):
            self.status_code, self.ok, self.text = status, status < 400, ''
            self.headers = {'Retry-After': '0', 'Content-Type': 'application/json'}

        def json(self):
            return {'status': 'Success', 'data': []}

    def fake(method, **kwargs):
        calls.append(method)
        return Reply(503 if len(calls) < 3 else 200)

    monkeypatch.setattr(ops.requests, 'request', fake)
    monkeypatch.setattr(ops.time, 'sleep', lambda s: None)
    ops._call(config, '/api/v3/tags')
    assert calls == ['GET', 'GET', 'GET']
    del calls[:]
    with pytest.raises(ConnectorError, match='HTTP 503'):
        ops._call(config, '/api/v3/indicators', 'POST', {'type': 'Address', 'ip': '198.51.100.1'})
    assert calls == ['POST']


@pytest.mark.parametrize('op', ['hunt_ip', 'hunt_file', 'hunt_email', 'hunt_url', 'hunt_host', 'get_indicator'])
def test_a_value_cannot_escape_its_path_segment(monkeypatch, run, op):
    """A value holding ? # & or / is one path segment: it must not add query parameters."""
    seen = []
    monkeypatch.setattr(ops, 'make_request', lambda *a, **k: seen.append(a[4]) or {'status': 'Success', 'data': {}})
    run(op, indicator='1.2.3.4?owner=Common Community&x=1#frag/../y')
    path, _, query = seen[0].partition('?')
    assert path == '/api/v3/indicators/1.2.3.4%3Fowner%3DCommon%20Community%26x%3D1%23frag%2F..%2Fy'
    assert query == 'owner=FortiLab%20Org'
