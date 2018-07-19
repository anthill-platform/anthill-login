from tornado.gen import coroutine, Return, sleep
from tornado.testing import gen_test

# noinspection PyUnresolvedReferences
from server import AuthServer

from common.testing import AcceptanceTestCase
from common.access import AccessToken
from common.sign import HMACAccessTokenSignature, RSAAccessTokenSignature
from common.access import scoped
import options as _opts

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

        os.write(pub, LoginAcceptanceTestCase.ANTHILL_KEY_PUB)
        os.write(pem, LoginAcceptanceTestCase.ANTHILL_KEY_PEM)

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
    @coroutine
    def co_setup_acceptance_tests(cls):

        yield cls.admin_action(
            "gamespace", "update", {
                "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE
            },
            title="Testing",
            scopes="gamespace_a,gamespace_b")

        yield cls.admin_action(
            "new_authoritative", "create", {},
            credential="dev:test01", password="test01")

        yield cls.admin_action(
            "new_authoritative", "create", {},
            credential="dev:test02", password="test02")

        result_01 = yield cls.admin_action(
            "accounts", "search_credential", {},
            credential="dev:test01")

        result_02 = yield cls.admin_action(
            "accounts", "search_credential", {},
            credential="dev:test02")

        cls.test01_account_id = str(result_01.context["account"])
        cls.test02_account_id = str(result_02.context["account"])

        yield cls.admin_action(
            "account", "update", {
                "account": cls.test01_account_id
            },
            rights="scope_a,scope_b,scope_c")

        yield cls.admin_action(
            "account", "update", {
                "account": cls.test02_account_id
            },
            rights="scope_a,scope_d")

    @gen_test
    def test_simple_auth(self):
        raw_token = yield self.post_success("auth", {
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
        self.assertEqual(token.scopes, ["gamespace_a", "scope_a"])

        yield self.validate_access_token(token)

    @gen_test
    def test_validation(self):
        raw_token = yield self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        response = yield self.get_success("validate", {
            "access_token": raw_token
        })

        self.assertEqual(response["account"], self.test01_account_id)
        self.assertEqual(response["credential"], "dev:test01")
        self.assertEqual(response["scopes"], ["gamespace_a", "scope_a"])

    @gen_test
    def test_invalidation(self):
        raw_token1 = yield self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        yield self.get_success("validate", {
            "access_token": raw_token1
        })

        raw_token2 = yield self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        yield self.get_success("validate", {
            "access_token": raw_token2
        })

        # previous token should be dead
        yield self.get_fail("validate", expected_code=403, query_args={
            "access_token": raw_token1
        })

    @gen_test
    def test_extend(self):
        test01 = yield self.post_success("auth", {
            "credential": "dev",
            "username": "test01",
            "key": "test01",
            "scopes": "gamespace_a,scope_a",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        yield self.validate_access_token(AccessToken(test01))

        test02 = yield self.post_success("auth", {
            "credential": "dev",
            "username": "test02",
            "key": "test02",
            "scopes": "scope_d",
            "gamespace": AcceptanceTestCase.TOKEN_GAMESPACE_NAME
        }, json_response=False)

        yield self.validate_access_token(AccessToken(test02))

        extended = yield self.post_success("extend", {
            "extend": test01,
            "access_token": test02,
            "scopes": "gamespace_a,scope_a,scope_d,scope_nonexisting"
        })

        self.assertEqual(extended["account"], self.test02_account_id)
        self.assertEqual(extended["scopes"], ["scope_d", "gamespace_a", "scope_a"])

        raw = extended["token"]
        extended_token = AccessToken(raw)

        self.assertEqual(extended_token.get(AccessToken.ACCOUNT), self.test02_account_id)
        self.assertEqual(extended_token.get(AccessToken.GAMESPACE), AcceptanceTestCase.TOKEN_GAMESPACE)
        self.assertEqual(extended_token.get(AccessToken.ISSUER), "login")
        self.assertEqual(extended_token.scopes, ["scope_d", "gamespace_a", "scope_a"])

        yield self.validate_access_token(AccessToken(test01))
        yield self.validate_access_token(AccessToken(test02))
        yield self.validate_access_token(extended_token)
