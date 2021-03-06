from tornado.gen import sleep
from tornado.testing import gen_test

from ..server import AuthServer
from .. import options as _opts

from anthill.common.handler import AuthenticatedHandler
from anthill.common.testing import AcceptanceTestCase
from anthill.common.access import AccessToken
from anthill.common.gen import AccessTokenGenerator
from anthill.common.sign import RSAAccessTokenSignature, TOKEN_SIGNATURE_RSA
from anthill.common.access import scoped

import tempfile
import os


class Test01AuthenticatedHandler(AuthenticatedHandler):
    @scoped(scopes=["test_a", "test_b"])
    def get(self):
        self.write("OK")


class Test02AuthenticatedHandler(AuthenticatedHandler):
    @scoped(scopes=["test_a", "test_b", "test_c"])
    def get(self):
        self.write("OK")


class AccessTokenTestCase(AcceptanceTestCase):
    TEST_CREDENTIAL = "dev:test01"
    AUTH_AS = "test"

    ANTHILL_KEY_PUB = """
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALyFNw4EntfQDgw9g60Uq0iBwRBG5gAV
LY9cmxPwEuq99gP3s+Ue3Bny6SicmQLDP+IfJMzPa+Vojhe+fOIV5OkCAwEAAQ==
-----END PUBLIC KEY-----
    """

    ANTHILL_KEY_PEM = """
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,2890CAACBB4DDD55

mdMxb8jLajUvfvkIzzTnlsVrsCqBplFQHlh9/nRdo7UhUwJ2neftDvT4DW1GBT7w
HfP5N47TmX64mHhSUSipDNDFmJ6hNxpSrG2UOYYTIv9UxrzqrY3l+qQXaXLINndh
AsTViNQfShAQDGLsD+Q+GQYIzMO5HDEV+0JiD5f6tU4W/ReS/6OFzU5Y2y/siMle
E6hdMXv5FNIfr2tWz+irRgDXdl8aF5Spr+wEyIxxemF1tWTOXadB+uk8TVx7J2Ga
u4Pi3QZS0sJn5kglMuXT41izX80+VbahApMtdxcKI62SobtqlF8hYatQj1TOnMYv
c+96WO+U14UHyA/cdXix1jM1w0TB80hRACOpr8njpr9nKB7+ggEWrVvLTHBc/gnm
jqhNID78KIZf+tf5oTHtwG/QsZEAE/ClmCoBL4+VILE=
-----END RSA PRIVATE KEY-----
    """

    ANTHILL_KEY_PEM_PASSWORD = "wYrA9O187G71ILmZr67GZG945SgarS4K"

    @classmethod
    def need_test_db(cls):
        return True

    @classmethod
    def get_server_instance(cls, db=None):
        return AuthServer(db)

    # noinspection PyUnresolvedReferences
    @classmethod
    async def co_setup_acceptance_tests(cls):
        cls.application.add_handlers(r".*", [
            (r"/test01", Test01AuthenticatedHandler),
            (r"/test02", Test02AuthenticatedHandler),
        ])

    @classmethod
    def setup_access_token(cls):

        pub, pub_path = tempfile.mkstemp(text=True)
        pem, pem_path = tempfile.mkstemp(text=True)

        os.write(pub, AccessTokenTestCase.ANTHILL_KEY_PUB.encode())
        os.write(pem, AccessTokenTestCase.ANTHILL_KEY_PEM.encode())

        AccessToken.init([RSAAccessTokenSignature(
            private_key=pem_path,
            password=AccessTokenTestCase.ANTHILL_KEY_PEM_PASSWORD,
            public_key=pub_path)])

        os.close(pub)
        os.close(pem)

    async def generate_access_token_key(self, allowed_scopes, credential=TEST_CREDENTIAL,
                                        account=AcceptanceTestCase.TOKEN_ACCOUNT,
                                        gamespace_id=AcceptanceTestCase.TOKEN_GAMESPACE,
                                        auth_as=AUTH_AS, unique=True, max_time=None):

        additional_containers = {
            AccessToken.ACCOUNT: str(account),
            AccessToken.GAMESPACE: str(gamespace_id)
        }

        if unique:
            additional_containers[AccessToken.ISSUER] = "login"

        res = AccessTokenGenerator.generate(
            TOKEN_SIGNATURE_RSA,
            allowed_scopes,
            additional_containers,
            credential,
            max_time=max_time)

        token = res["key"]
        uuid = res["uuid"]
        expires = res["expires"]
        scopes = res["scopes"]

        # store the token in key/value storage
        if unique:
            await self.application.tokens.save_token(account, uuid, expires, name=auth_as)

        return token

    async def generate_access_token(self, *args, **kwargs):
        key = await self.generate_access_token_key(*args, **kwargs)
        return AccessToken(key)

    async def check_token(self, scopes):
        key = await self.generate_access_token_key(scopes)
        token = AccessToken(key)
        self.assertTrue(token.is_valid(), "Generated access token is not valid")
        self.assertEqual(token.get(AccessToken.ACCOUNT), AcceptanceTestCase.TOKEN_ACCOUNT)
        self.assertEqual(token.get(AccessToken.GAMESPACE), AcceptanceTestCase.TOKEN_GAMESPACE)
        self.assertEqual(token.get(AccessToken.USERNAME), AccessTokenTestCase.TEST_CREDENTIAL)
        self.assertEqual(token.get(AccessToken.ISSUER), "login")
        self.assertIn(AccessToken.EXPIRATION_DATE, token.fields)
        self.assertIn(AccessToken.ISSUED_AT, token.fields)
        self.assertIn(AccessToken.UUID, token.fields)
        self.assertSetEqual(token.scopes, scopes)

    @gen_test
    async def test_token(self):
        await self.check_token({"test_a"})
        await self.check_token({"test_a", "test_b"})
        await self.check_token(set())

    @gen_test
    async def test_validation(self):
        token = await self.generate_access_token(["test_a", "test_b"])
        self.assertTrue((await self.application.tokens.validate(token)), "Generated access token is not valid")

    @gen_test
    async def test_expiration(self):
        token = await self.generate_access_token(["test_a", "test_b"], max_time=1)
        self.assertTrue((await self.application.tokens.validate(token)), "Generated access token is not valid")
        await sleep(2)
        self.assertFalse((await self.application.tokens.validate(token)),
                         "Access token should not be valid at that point")

    @gen_test
    async def test_invalidation(self):
        token = await self.generate_access_token(["test_a", "test_b"], max_time=1)
        self.assertTrue((await self.application.tokens.validate(token)), "Generated access token is not valid")
        await self.application.tokens.invalidate_uuid(token.get(AccessToken.ACCOUNT), token.get(AccessToken.UUID))
        self.assertFalse((await self.application.tokens.validate(token)),
                         "Access token should not be valid at that point")

    @gen_test
    async def test_as(self):
        token1 = await self.generate_access_token(
            ["test_a", "test_b"], auth_as="test1")
        self.assertTrue((await self.application.tokens.validate(token1)), "Generated access token is not valid")
        # generate second token with the same `auth_as` option
        token2 = await self.generate_access_token(["test_a", "test_b"], auth_as="test1")
        self.assertTrue((await self.application.tokens.validate(token2)), "Generated access token is not valid")
        self.assertFalse((await self.application.tokens.validate(token1)),
                         "Access token should not be valid at that point")

    @gen_test
    async def test_unique(self):
        token1 = await self.generate_access_token(
            ["test_a", "test_b"], auth_as="test1", unique=False)
        self.assertTrue((await self.application.tokens.validate(token1)), "Generated access token is not valid")
        # generate second token with the same `auth_as` option
        token2 = await self.generate_access_token(["test_a", "test_b"], auth_as="test1", unique=False)
        self.assertTrue((await self.application.tokens.validate(token2)), "Generated access token is not valid")
        self.assertTrue((await self.application.tokens.validate(token1)),
                        "Access token should be still valid at that point")

    @gen_test
    async def test_handler(self):
        key = await self.generate_access_token_key(["test_a", "test_b"])

        await self.get_success("test01", query_args={"access_token": key}, pass_access_token=False, json_response=False)
        await self.get_fail("test02", 403, query_args={"access_token": key}, pass_access_token=False)
