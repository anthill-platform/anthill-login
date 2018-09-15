
import logging
from urllib import parse

from .. model import authenticator
from .. model.authenticator import AuthenticationResult
from .. model.key import KeyNotFound
from . import SocialAuthenticator

from anthill.common.social.apis import FacebookAPI
from anthill.common.social import APIError


CREDENTIAL_TYPE = "facebook"


class FacebookAuthenticator(SocialAuthenticator, FacebookAPI):
    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, FacebookAPI.NAME)
        FacebookAPI.__init__(self, None)

    async def authorize(self, gamespace, args, db=None, env=None):

        try:
            code = args["code"]
            redirect_uri = args["redirect_uri"]
        except KeyError:
            raise authenticator.AuthenticationError("missing_argument")

        try:
            result = await self.api_auth(gamespace, code=code, redirect_uri=redirect_uri)
        except APIError as e:
            logging.exception("api error")
            raise authenticator.AuthenticationError("API error:" + e.body, e.code)

        username = args.get("username", None)

        if not username:
            info = await self.api_get_user_info(gamespace, access_token=result.access_token, fields="id", parse=False)
            username = info["id"]

        auth_result = AuthenticationResult(
            credential=self.type(),
            username=username,
            response=result)

        return auth_result

    def generate_login_url(self, app_id, redirect_uri):

        return "https://www.facebook.com/dialog/oauth/?" + parse.urlencode({
            "scope": "public_profile,user_friends",
            "client_id": app_id,
            "redirect_uri": redirect_uri,
            "response_type": "code"
        })

    def social_profile(self):
        return True

    def has_auth_form(self):
        return True
