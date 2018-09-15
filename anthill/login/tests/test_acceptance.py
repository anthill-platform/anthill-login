
from tornado.testing import gen_test

from .. server import AuthServer
from .. import options as _opts

from anthill.common.testing import AcceptanceTestCase
from anthill.common.access import AccessToken
from anthill.common.sign import HMACAccessTokenSignature, RSAAccessTokenSignature
from anthill.common.access import scoped

import tempfile
import os
import ujson


class LoginAcceptanceTestCase(AcceptanceTestCase):
    AUTH_AS = "test"

    ANTHILL_KEY_PUB = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALyFNw4EntfQDgw9g60Uq0iBwRBG5gAV
LY9cmxPwEuq99gP3s+Ue3Bny6SicmQLDP+IfJMzPa+Vojhe+fOIV5OkCAwEAAQ==
-----END PUBLIC KEY-----
"""

    ANTHILL_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,2890CAACBB4DDD55

mdMxb8jLajUvfvkIzzTnlsVrsCqBplFQHlh9/nRdo7UhUwJ2neftDvT4DW1GBT7w
HfP5N47TmX64mHhSUSipDNDFmJ6hNxpSrG2UOYYTIv9UxrzqrY3l+qQXaXLINndh
AsTViNQfShAQDGLsD+Q+GQYIzMO5HDEV+0JiD5f6tU4W/ReS/6OFzU5Y2y/siMle
E6hdMXv5FNIfr2tWz+irRgDXdl8aF5Spr+wEyIxxemF1tWTOXadB+uk8TVx7J2Ga
u4Pi3QZS0sJn5kglMuXT41izX80+VbahApMtdxcKI62SobtqlF8hYatQj1TOnMYv
c+96WO+U14UHyA/cdXix1jM1w0TB80hRACOpr8njpr9nKB7+ggEWrVvLTHBc/gnm
jqhNID78KIZf+tf5oTHtwG/QsZEAE/ClmCoBL4+VILE=
-----END RSA PRIVATE KEY-----"""

    ANTHILL_KEY_PEM_PASSWORD = "wYrA9O187G71ILmZr67GZG945SgarS4K"

    @classmethod
    def need_test_db(cls):
        return True

    @classmethod
    def get_server_instance(cls, db=None):
        return AuthServer(db)

    @classmethod
    def setup_access_token(cls):
        pub, pub_path = tempfile.mkstemp(text=True)
        pem, pem_path = tempfile.mkstemp(text=True)

        os.write(pub, LoginAcceptanceTestCase.ANTHILL_KEY_PUB.encode())
        os.write(pem, LoginAcceptanceTestCase.ANTHILL_KEY_PEM.encode())

        AccessToken.init([
            HMACAccessTokenSignature(key=AcceptanceTestCase.TESTING_KEY),
            RSAAccessTokenSignature(
                private_key=pem_path,
                password=LoginAcceptanceTestCase.ANTHILL_KEY_PEM_PASSWORD,
                public_key=pub_path)])

        os.close(pub)
        os.close(pem)

    def validate_access_token(self, token):
        return self.application.tokens.validate(token)

    @classmethod
    async def co_setup_acceptance_tests(cls):

        await cls.admin_action(
            "gamespace", "update", {
                "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE
            },
            title="Testing",
            scopes="gamespace_a,gamespace_b")

        await cls.admin_action(
            "new_authoritative", "create", {},
            credential="dev:test01", password="test01")

        await cls.admin_action(
            "new_authoritative", "create", {},
            credential="dev:test02", password="test02")

        result_01 = await cls.admin_action(
            "accounts", "search_credential", {},
            credential="dev:test01")

        result_02 = await cls.admin_action(
            "accounts", "search_credential", {},
            credential="dev:test02")

        cls.test01_account_id = str(result_01.context["account"])
        cls.test02_account_id = str(result_02.context["account"])

        await cls.admin_action(
            "account", "update", {
                "account": cls.test01_account_id
            },
            rights="scope_a,scope_b,scope_c")

        await cls.admin_action(
            "account", "update", {
                "account": cls.test02_account_id
            },
            rights="scope_a,scope_d")

    @gen_test
    async def test_simple_auth(self):
        raw_token = await self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        token = AccessToken(raw_token)
        self.assertEqual(token.get(AccessToken.ACCOUNT), self.test01_account_id)
        self.assertEqual(token.get(AccessToken.GAMESPACE), AcceptanceTestCase.TOKEN_GAMESPACE)
        self.assertEqual(token.get(AccessToken.ISSUER), "login")
        self.assertSetEqual(token.scopes, {"gamespace_a", "scope_a"})

        await self.validate_access_token(token)

    @gen_test
    async def test_validation(self):
        raw_token = await self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        response = await self.get_success("validate", {
            "access_token": raw_token
        })

        self.assertEqual(response["account"], self.test01_account_id)
        self.assertEqual(response["credential"], "dev:test01")
        self.assertSetEqual(set(response["scopes"]), {"gamespace_a", "scope_a"})

    @gen_test
    async def test_invalidation(self):
        raw_token1 = await self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        await self.get_success("validate", {
            "access_token": raw_token1
        })

        raw_token2 = await self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        await self.get_success("validate", {
            "access_token": raw_token2
        })

        # previous token should be dead
        await self.get_fail("validate", expected_code=403, query_args={
            "access_token": raw_token1
        })

    @gen_test
    async def test_extend(self):
        test01 = await self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        await self.validate_access_token(AccessToken(test01))

        test02 = await self.post_success("auth", {
            "credential": "dev",
            "username": "test02",
            "key": "test02",
            "scopes": "scope_d",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        await self.validate_access_token(AccessToken(test02))

        extended = await self.post_success("extend", {
            "extend": test01,
            "access_token": test02,
            "scopes": "gamespace_a,scope_a,scope_d,scope_nonexisting"
        })

        self.assertEqual(extended["account"], self.test02_account_id)
        self.assertSetEqual(set(extended["scopes"]), {"scope_d", "gamespace_a", "scope_a"})

        raw = extended["token"]
        extended_token = AccessToken(raw)

        self.assertEqual(extended_token.get(AccessToken.ACCOUNT), self.test02_account_id)
        self.assertEqual(extended_token.get(AccessToken.GAMESPACE), AcceptanceTestCase.TOKEN_GAMESPACE)
        self.assertEqual(extended_token.get(AccessToken.ISSUER), "login")
        self.assertEqual(extended_token.scopes, {"scope_d", "gamespace_a", "scope_a"})

        await self.validate_access_token(AccessToken(test01))
        await self.validate_access_token(AccessToken(test02))
        await self.validate_access_token(extended_token)
