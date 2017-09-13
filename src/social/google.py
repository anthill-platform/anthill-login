
from tornado.gen import coroutine, Return

from model import authenticator
from model.authenticator import AuthenticationResult
from model.key import KeyNotFound
from . import SocialAuthenticator

import logging
import urllib

from common.social import APIError
from common.social.google import GoogleAPI, GooglePrivateKey


CREDENTIAL_TYPE = "google"


class GoogleAuthenticator(SocialAuthenticator, GoogleAPI):
    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, CREDENTIAL_TYPE)
        GoogleAPI.__init__(self, None)

    @coroutine
    def authorize(self, gamespace, args, db=None):
        try:
            code = args["code"]
            redirect_uri = args["redirect_uri"]
        except KeyError:
            raise authenticator.AuthenticationError("missing_argument")

        try:
            result = yield self.api_auth(gamespace, code, redirect_uri)
        except APIError as e:
            logging.exception("api error")
            raise authenticator.AuthenticationError("API error:" + e.body, e.code)
        else:
            auth_result = AuthenticationResult(credential=self.type(),
                                               username=result.username,
                                               response=result)

            raise Return(auth_result)

    def generate_login_url(self, app_id, redirect_url):
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.urlencode({
            "scope": "profile email",
            "client_id": app_id,
            "redirect_uri": redirect_url,
            "display": "popup",
            "response_type": "code",
            "access_type": "offline"
        })

    def social_profile(self):
        return True

    def has_auth_form(self):
        return True
