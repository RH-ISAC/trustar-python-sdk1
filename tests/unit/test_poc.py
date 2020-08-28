import pytest
from requests.exceptions import HTTPError
from trustar.trustar import TruStar


def test_trustar_get_enclaves(mocked_request, get_user_enclaves_fixture):
    trustar_client = TruStar()
    mocked_request.get(url="/api/1.3/enclaves", json=get_user_enclaves_fixture)
    assert len(trustar_client.get_user_enclaves()) == 4


def test_trustar_get_exception(mocked_request):
    trustar_client = TruStar()
    mocked_request.get(url="/api/1.3/enclaves", exc=HTTPError)
    with pytest.raises(HTTPError):
        trustar_client.get_user_enclaves()
