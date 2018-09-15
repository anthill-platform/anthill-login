
import tornado.httpclient
import logging
import base64
from urllib import parse
from OpenSSL import crypto
import struct

from .. model.authenticator import AuthenticationResult, AuthenticationError
from . import SocialAuthenticator

from anthill.common import cached


class GameCenterAuthorizer(SocialAuthenticator):
    TYPE = "gamecenter"

    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, GameCenterAuthorizer.TYPE)

    async def authorize(self, gamespace, args, db=None, env=None):
        try:
            public_key_url = args["public_key"]
            signature = args["signature"]
            salt = args["salt"]
            timestamp = args["timestamp"]
            bundle_id = args["bundle_id"]
            username = args["username"]
        except KeyError:
            logging.error("Missing arguments")
            raise AuthenticationError("missing_argument")

        try:
            decoded_sig = base64.b64decode(signature)
            decoded_salt = base64.b64decode(salt)
        except Exception:
            logging.error("Failed to decode signature or salt")
            raise AuthenticationError("error")

        try:
            key_parsed = parse.urlparse(public_key_url)
        except Exception:
            logging.error("Failed to parse public key")
            raise AuthenticationError("error")
        else:
            if (key_parsed.scheme != "https") or (not key_parsed.hostname.endswith("apple.com")):
                logging.error("Wrong certificate location")
                raise AuthenticationError("forbidden")

            key_url = parse.urlunparse(key_parsed)

        # noinspection PyUnusedLocal
        @cached(kv=self.application.cache,
                h=lambda: "cert:" + key_url,
                ttl=600)
        async def get_certificate(location, *i_args, **i_kwargs):
            client = tornado.httpclient.AsyncHTTPClient()
            result = await client.fetch(location)
            return result.body

        try:
            certificate = await get_certificate(key_url)
        except tornado.httpclient.HTTPError as e:
            logging.error("Failed to download certificate: " + str(e.code))
            raise AuthenticationError("error")

        try:
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
        except Exception as e:
            logging.error("Failed to load certificate: " + str(e))
            raise AuthenticationError("forbidden")

        payload = username.encode('UTF-8') + bundle_id.encode('UTF-8') + \
            struct.pack('>Q', int(timestamp)) + decoded_salt

        try:
            crypto.verify(x509, decoded_sig, payload, 'sha256')
        except Exception as err:
            logging.error("Failed to verify signature: " + str(err))
            raise AuthenticationError("forbidden")
        else:
            logging.info('Successfully verified certificate with signature')

        auth_result = AuthenticationResult(credential=self.type(),
                                           username=username,
                                           response=None)

        return auth_result

    def social_profile(self):
        return False

    def new_private_key(self, data):
        raise NotImplementedError()
