"""Guards: every operation in info.json is implemented and exercised, and the source stays ASCII."""
import json
import re
from pathlib import Path

from conftest import CONNECTOR_DIR, operations as ops

TESTS = Path(__file__).parent
INFO = json.loads((CONNECTOR_DIR / 'info.json').read_text())


def test_every_info_operation_is_implemented_and_every_implementation_is_declared():
    assert {o['operation'] for o in INFO['operations']} == set(ops.operations)


def test_every_operation_has_a_test():
    text = (TESTS / 'test_operations.py').read_text()
    missing = [o['operation'] for o in INFO['operations']
               if not re.search(r"""['"]%s['"]""" % o['operation'], text)]
    assert not missing, 'operations with no test: %s' % missing


def test_dropdown_populators_exist_and_are_hidden():
    populators = {p['apiOperation'] for o in INFO['operations'] for p in o['parameters'] if p.get('apiOperation')}
    assert populators == {'get_owner_options'}
    hidden = {o['operation'] for o in INFO['operations'] if not o.get('visible', True)}
    assert populators <= hidden


def test_connector_source_is_ascii():
    """FortiSOAR loads connector source as latin-1: one stray dash raises UnicodeEncodeError."""
    bad = [str(p) for p in CONNECTOR_DIR.glob('*.py') if re.search(r'[^\x00-\x7f]', p.read_text())]
    assert not bad, bad


def test_playbook_collection_matches_the_connector_version():
    name = json.loads((CONNECTOR_DIR / 'playbooks' / 'playbooks.json').read_text())['data'][0]['name']
    assert name.endswith(INFO['version'])
