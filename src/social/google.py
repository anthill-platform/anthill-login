
from tornado.gen import coroutine, Return

from model import authenticator
from model.authenticator import AuthenticationResult
from model.key import KeyNotFound
from . import SocialAuthenticator

import logging

from common.social import APIError
from common.social.google import GoogleAPI, GooglePrivateKey


class GoogleAuthenticator(SocialAuthenticator, GoogleAPI):
    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, "google")
        GoogleAPI.__init__(self, None)

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
        else:
            auth_result = AuthenticationResult(credential=self.type(),
                                               username=result.username,
                                               response=result)

            raise Return(auth_result)

    def social_profile(self):
        return True
