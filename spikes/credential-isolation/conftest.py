import pytest


# anyio backend fixture — required for @pytest.mark.anyio tests.
@pytest.fixture(params=["asyncio"])
def anyio_backend(request: pytest.FixtureRequest) -> str:
    return str(request.param)
