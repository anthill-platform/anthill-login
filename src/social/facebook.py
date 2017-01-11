import tornado.httpclient

from tornado.gen import coroutine, Return

import logging

from model import authenticator
from model.authenticator import AuthenticationResult
from model.key import KeyNotFound
from . import SocialAuthenticator

from common.social.facebook import FacebookAPI, FacebookPrivateKey
from common.social import APIError


class FacebookAuthenticator(SocialAuthenticator, FacebookAPI):
    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, "facebook")
        FacebookAPI.__init__(self, None)

    @coroutine
    def authorize(self, gamespace, args, db=None):
        try:
            key = args["key"]
        except KeyError:
            raise authenticator.AuthenticationError("missing_argument")

        try:
            result = yield self.api_auth(gamespace, key)
        except APIError as e:
            logging.exception("api error")
            raise authenticator.AuthenticationError("API error:" + e.body, e.code)

        auth_result = AuthenticationResult(
            credential=self.type(),
            username=args["username"],
            response=result)

        raise Return(auth_result)

    def social_profile(self):
        return True
