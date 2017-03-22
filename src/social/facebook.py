import tornado.httpclient

from tornado.gen import coroutine, Return

import logging
import urllib

from model import authenticator
from model.authenticator import AuthenticationResult
from model.key import KeyNotFound
from . import SocialAuthenticator

from common.social.facebook import FacebookAPI, FacebookPrivateKey
from common.social import APIError


CREDENTIAL_TYPE = "facebook"


class FacebookAuthenticator(SocialAuthenticator, FacebookAPI):
    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, CREDENTIAL_TYPE)
        FacebookAPI.__init__(self, None)

    @coroutine
    def authorize(self, gamespace, args, db=None):

        key = args.get("key", None)
        code = args.get("code", None)
        redirect_uri = args.get("redirect_uri", None)

        if not key and not code:
            raise authenticator.AuthenticationError("missing_argument")

        try:
            result = yield self.api_auth(gamespace, key=key, code=code, redirect_uri=redirect_uri)
        except APIError as e:
            logging.exception("api error")
            raise authenticator.AuthenticationError("API error:" + e.body, e.code)

        username = args.get("username", None)

        if not username:
            info = yield self.api_get_user_info(gamespace, access_token=result.access_token, fields="id", parse=False)
            username = info["id"]

        auth_result = AuthenticationResult(
            credential=self.type(),
            username=username,
            response=result)

        raise Return(auth_result)

    def generate_login_url(self, app_id, redirect_url):

        return "https://www.facebook.com/dialog/oauth/?" + urllib.urlencode({
            "scope": "public_profile,user_friends",
            "client_id": app_id,
            "redirect_uri": redirect_url,
            "response_type": "code"
        })

    def social_profile(self):
        return True
