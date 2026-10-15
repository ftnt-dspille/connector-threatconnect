"""STIX / TAXII 2.1: the connector against the mock's ThreatConnect TAXII server (real HTTP, Basic auth)."""
import pytest
import requests

from conftest import ConnectorError, TAXII_PASS, TAXII_USER, operations as ops

V1 = '/api/services/taxii/v1'


def _extra_owner(server, count=3):
    for i in range(count):
        row = dict(server.ds.rows[i], id=9000 + i, summary='198.51.100.%d' % (200 + i), type='Address',
                   ownerName='Lab Source')
        server.ds.add(row)


# -- collections ---------------------------------------------------------------

def test_taxii_list_collections_has_one_collection_per_owner(run, server):
    _extra_owner(server)
    titles = [c['title'] for c in run('taxii_list_collections')['collections']]
    assert titles == ['FortiLab Org', 'Lab Source']


def test_get_collection_options_lists_collection_titles(run, server):
    _extra_owner(server)
    assert run('get_collection_options') == ['FortiLab Org', 'Lab Source']


def test_a_collection_can_be_addressed_by_id_or_by_name(run, server):
    cid = run('taxii_list_collections')['collections'][0]['id']
    by_id = run('taxii_get_objects', collection=cid, limit=3)
    by_name = run('taxii_get_objects', collection='FortiLab Org', limit=3)
    assert by_id['objects'] == by_name['objects']


def test_an_unknown_collection_is_a_readable_error(run):
    with pytest.raises(ConnectorError, match='HTTP 404 GET .*collections/Nope/objects: Collection Nope not found'):
        run('taxii_get_objects', collection='Nope')


# -- raw pages -----------------------------------------------------------------

def test_taxii_get_objects_pages_with_more_and_next(run, server):
    seen, cursor = [], None
    while True:
        page = run('taxii_get_objects', collection='FortiLab Org', limit=25, next=cursor)
        seen += [o['id'] for o in page['objects'] if o['type'] == 'indicator']
        if not page['more']:
            break
        cursor = page['next']
    assert len(seen) == len(set(seen)) == len(server.ds.rows)


def test_a_page_carries_the_tlp_markings_its_indicators_reference(run):
    objects = run('taxii_get_objects', collection='FortiLab Org', limit=20)['objects']
    markings = {o['id'] for o in objects if o['type'] == 'marking-definition'}
    refs = {r for o in objects if o['type'] == 'indicator' for r in o['object_marking_refs']}
    assert refs and refs <= markings


def test_an_empty_result_has_no_objects_key_and_the_connector_copes(run):
    page = run('taxii_get_objects', collection='FortiLab Org', added_after='2099-01-01T00:00:00Z')
    assert page == {'more': False, 'objects': []}


# -- bulk pull -----------------------------------------------------------------

def test_fetch_stix_indicators_pulls_everything(run, server):
    result = run('fetch_stix_indicators', page_size=7)
    assert result['count'] == len(server.ds.rows) and not result['truncated'] and result['skipped'] == 0
    assert len({i['stix_id'] for i in result['indicators']}) == result['count']


def test_stix_records_match_the_v3_records_for_the_same_indicators(run, server):
    """The ingestion mapping is shared, so the STIX record must say what the v3 record says."""
    import arrow
    v3 = {i['summary']: i for i in run('fetch_indicators')['indicators']}
    stix = {i['summary']: i for i in run('fetch_stix_indicators')['indicators']}
    assert set(v3) == set(stix)
    for summary, rec in stix.items():
        want = v3[summary]
        assert (rec['type'], rec['ownerName'], rec['confidence'], rec['rating'], rec['description']) == \
            (want['type'], want['ownerName'], want['confidence'], want['rating'], want['description'])
        assert arrow.get(rec['lastModified']) == arrow.get(want['lastModified'])
        assert arrow.get(rec['dateAdded']) == arrow.get(want['dateAdded'])
        assert rec['tags'] == sorted(set(want['tags']))
        assert rec['tlp'] in ('Red', 'Amber', 'Green', 'White')


def test_every_indicator_type_round_trips_through_its_stix_pattern(run, server):
    stix = {i['summary']: i['type'] for i in run('fetch_stix_indicators')['indicators']}
    assert stix == {r['summary']: r['type'] for r in server.ds.rows}


def test_fetch_stix_indicators_filters_by_type_and_honours_the_limit(run):
    hosts = run('fetch_stix_indicators', indicator_type='Host')
    assert hosts['count'] == 12 and {i['type'] for i in hosts['indicators']} == {'Host'}
    capped = run('fetch_stix_indicators', limit=5)
    assert capped['count'] == 5 and capped['truncated'] is True


@pytest.mark.parametrize('server_honours_added_after', [True, False])
def test_the_cursor_works_whether_or_not_the_server_implements_added_after(run, server, server_honours_added_after):
    """added_after is undocumented by ThreatConnect: the result must not depend on it."""
    server.mock.Handler.taxii_added_after = server_honours_added_after
    everything = run('fetch_stix_indicators')['indicators']
    cut = sorted(i['lastModified'] for i in everything)[30]
    result = run('fetch_stix_indicators', modified_since=cut)
    assert {i['summary'] for i in result['indicators']} == \
        {i['summary'] for i in everything if i['lastModified'] >= cut}
    assert 0 < result['count'] < len(everything)
    assert run('fetch_stix_indicators', modified_since='2099-01-01T00:00:00Z')['count'] == 0


def test_a_zero_or_blank_cursor_means_pull_everything(run, server):
    for cursor in ('0', '', None):
        assert run('fetch_stix_indicators', modified_since=cursor)['count'] == len(server.ds.rows)


def test_a_bad_cursor_is_a_readable_error(run):
    with pytest.raises(ConnectorError, match='Modified Since must be an ISO 8601 datetime'):
        run('fetch_stix_indicators', modified_since='yesterday-ish')


def test_with_no_owner_and_no_default_every_collection_is_pulled(server, config):
    _extra_owner(server)
    config['api_default_org'] = None
    from threatconnect.connector import ThreatConnect
    result = ThreatConnect().execute(config, 'fetch_stix_indicators', {})
    assert result['count'] == len(server.ds.rows) and result['collections'] == 2


def test_an_owner_limits_the_pull_to_its_collection(run, server):
    _extra_owner(server)
    result = run('fetch_stix_indicators', owner='Lab Source')
    assert result['count'] == 3 and {i['ownerName'] for i in result['indicators']} == {'Lab Source'}


def test_the_app_1_0_base_path_works(server, config):
    config['taxii_base_path'] = V1
    from threatconnect.connector import ThreatConnect
    assert ThreatConnect().execute(config, 'fetch_stix_indicators', {})['count'] == len(server.ds.rows)


# -- auth ----------------------------------------------------------------------

def test_taxii_needs_the_taxii_credentials(server, config):
    config.pop('taxii_password')
    from threatconnect.connector import ThreatConnect
    with pytest.raises(ConnectorError, match='TAXII Username and TAXII Password are required'):
        ThreatConnect().execute(config, 'taxii_list_collections', {})


def test_a_wrong_taxii_password_is_a_401(server, config):
    config['taxii_password'] = 'nope'
    from threatconnect.connector import ThreatConnect
    with pytest.raises(ConnectorError, match='HTTP 401 GET .*collections: Unauthorized'):
        ThreatConnect().execute(config, 'taxii_list_collections', {})


def test_the_v3_schemes_are_refused_on_taxii_and_basic_is_refused_on_v3(server):
    base = server.url + '/api/services/taxii/v2/taxii/tc_taxii/collections'
    accept = {'Accept': ops.TAXII_MEDIA}
    assert requests.get(base, headers={**accept, 'Authorization': 'TC-Token test-pat'}).status_code == 401
    assert requests.get(base, headers=accept, auth=(TAXII_USER, TAXII_PASS)).status_code == 200
    assert requests.get(server.url + '/api/v3/indicators', auth=(TAXII_USER, TAXII_PASS)).status_code == 401


def test_the_server_insists_on_the_taxii_media_type(server):
    base = server.url + '/api/services/taxii/v2/taxii/tc_taxii'
    assert requests.get(base, auth=(TAXII_USER, TAXII_PASS), headers={'Accept': 'application/json'}).status_code == 406
    assert requests.get(base, auth=(TAXII_USER, TAXII_PASS), headers={'Accept': ops.TAXII_MEDIA}).status_code == 200


# -- pattern parsing -----------------------------------------------------------

def test_a_multi_hash_file_pattern_becomes_md5_sha1_sha256_in_v3_order():
    md5, sha1, sha256 = 'a' * 32, 'b' * 40, 'c' * 64
    pattern = "[file:hashes.'SHA-256' = '%s' AND file:hashes.'MD5' = '%s' OR file:hashes.'SHA-1' = '%s']" % (sha256, md5, sha1)
    assert ops._stix_value(pattern) == ('File', ' : '.join([md5, sha1, sha256]))


def test_an_escaped_quote_in_a_pattern_value_is_unescaped():
    assert ops._stix_value(r"[url:value = 'https://example.com/it\'s']") == ('URL', "https://example.com/it's")


@pytest.mark.parametrize('pattern,expected', [
    ("[ipv4-addr:value = '10.10.1.16/32']", ('Address', '10.10.1.16/32')),
    ("[ipv6-addr:value = '2001:db8::1']", ('Address', '2001:db8::1')),
    ("[domain-name:value = 'example.com']", ('Host', 'example.com')),
    ("[email-addr:value = 'a@example.com']", ('EmailAddress', 'a@example.com')),
    ("[mutex:name = 'x']", None),
    ("[autonomous-system:number = 'x']", None),
    ("[ipv4-addr:value = '1.1.1.1' OR domain-name:value = 'example.com']", None),
    ('', None),
])
def test_stix_patterns_map_to_threatconnect_types(pattern, expected):
    assert ops._stix_value(pattern) == expected


def test_unsupported_and_non_indicator_objects_are_skipped_and_counted(server, config):
    import json
    from threatconnect.connector import ThreatConnect
    objects = [
        {'type': 'indicator', 'id': 'indicator--1', 'pattern': "[mutex:name = 'x']", 'pattern_type': 'stix'},
        {'type': 'malware', 'id': 'malware--1'},
        {'type': 'indicator', 'id': 'indicator--2', 'pattern': "[ipv4-addr:value = '203.0.113.9']",
         'pattern_type': 'stix', 'created': '2026-10-10T00:00:00.000Z', 'modified': '2026-10-10T00:00:00.000Z',
         'x_threatconnect_id': 7, 'x_threatconnect_owner': 'FortiLab Org'},
    ]
    original = ops._taxii_call

    def fake(cfg, path):
        return {'more': False, 'objects': objects} if '/objects' in path else original(cfg, path)

    ops._taxii_call = fake
    try:
        result = ThreatConnect().execute(config, 'fetch_stix_indicators', {})
    finally:
        ops._taxii_call = original
    assert result['count'] == 1 and result['skipped'] == 2 and result['indicators'][0]['id'] == '7'
    json.dumps(result)
