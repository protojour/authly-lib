import pytest

from authly import Authly

@pytest.mark.asyncio
async def test_authly_connect():
    authly = Authly()
    await authly.connect(
        url="https://localhost:1443",
        ca_path=".local/etc/authly/certs/local.crt",
        id_path=".local/etc/authly/service/s.f3e799137c034e1eb4cd3e4f65705932/identity.pem",
    )


