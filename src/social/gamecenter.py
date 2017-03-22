
from tornado.gen import coroutine, Return

import tornado.httpclient
import logging
import base64
import urlparse
from OpenSSL import crypto
import struct

from model.authenticator import AuthenticationResult
from model import authenticator
from . import SocialAuthenticator

from common import cached


CREDENTIAL_TYPE = "gamecenter"


class GameCenterAuthorizer(SocialAuthenticator):

    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, CREDENTIAL_TYPE)

    @coroutine
    def authorize(self, gamespace, args, db=None):
        try:
            public_key_url = args["public_key"]
            signature = args["signature"]
            salt = args["salt"]
            timestamp = args["timestamp"]
            bundle_id = args["bundle_id"]
            username = args["username"]
        except KeyError:
            logging.error("Missing arguments")
            raise authenticator.AuthenticationError("missing_argument")

        try:
            decoded_sig = base64.b64decode(signature)
            decoded_salt = base64.b64decode(salt)
        except:
            logging.error("Failed to decode signature or salt")
            raise authenticator.AuthenticationError("error")

        try:
            key_parsed = urlparse.urlparse(public_key_url)
        except:
            logging.error("Failed to parse public key")
            raise authenticator.AuthenticationError("error")
        else:
            if (key_parsed.scheme != "https") or (not key_parsed.hostname.endswith("apple.com")):
                logging.error("Wrong certificate location")
                raise authenticator.AuthenticationError("forbidden")

            key_url = urlparse.urlunparse(key_parsed)

        @cached(kv=self.application.cache,
                h=lambda: "cert:" + key_url,
                ttl=600)
        @coroutine
        def get_certificate(location, *args, **kwargs):
            client = tornado.httpclient.AsyncHTTPClient()
            result = yield client.fetch(location)
            raise Return(result.body)

        try:
            certificate = yield get_certificate(key_url)
        except tornado.httpclient.HTTPError as e:
            logging.error("Failed to download certificate: " + str(e.code))
            raise authenticator.AuthenticationError("error")

        try:
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
        except Exception as e:
            logging.error("Failed to load certificate: " + e.message)
            raise authenticator.AuthenticationError("forbidden")

        payload = username.encode('UTF-8') + bundle_id.encode('UTF-8') + \
            struct.pack('>Q', int(timestamp)) + decoded_salt

        try:
            crypto.verify(x509, decoded_sig, payload, 'sha256')
        except Exception as err:
            logging.error("Failed to verify signature: " + str(err))
            raise authenticator.AuthenticationError("forbidden")
        else:
            logging.info('Successfully verified certificate with signature')

        auth_result = AuthenticationResult(credential=self.type(),
                                           username=username,
                                           response=None)

        raise Return(auth_result)

    def social_profile(self):
        return False

    def new_private_key(self, data):
        raise NotImplementedError()
