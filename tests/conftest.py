import pytest
import requests_mock

@pytest.fixture
def mocked_request():
    with requests_mock.Mocker() as m:
        m.post(url="/oauth/token", text='{"access_token": "XXXXXXXXXXXXXXXXXXX"}')
        yield m

@pytest.fixture
def get_user_enclaves_fixture():
    return [{'id': 'xxxxxxx-xxx-xxxx-xxxx-xxxxxxxxxxxx', 'name': 'Community',
             'type': 'COMMUNITY', 'read': True, 'create': True, 'update': False},
            {'id': 'xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxxxxxxx', 'name': 'ncfta_stash',
             'type': 'INTERNAL', 'read': True, 'create': True, 'update': True},
            {'id': 'xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxxxxxxx',
             'name': 'not a real enclave',
             'type': 'INTERNAL', 'read': True, 'create': True, 'update': True},
            {'id': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
             'name': 'Nemo Research',
             'type': 'RESEARCH', 'read': True, 'create': False, 'update': False}]
