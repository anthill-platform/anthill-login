
from .. model import authenticator
from .. model.authenticator import AuthenticationResult
from .. model.key import KeyNotFound
from . import SocialAuthenticator

import logging
from urllib import parse

from anthill.common.social import APIError
from anthill.common.social.apis import VKAPI


CREDENTIAL_TYPE = "vk"


class VKAuthenticator(SocialAuthenticator, VKAPI):
    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, VKAPI.NAME)
        VKAPI.__init__(self, None)

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
        else:
            auth_result = AuthenticationResult(credential=self.type(),
                                               username=result.username,
                                               response=result)

            return auth_result

    def generate_login_url(self, app_id, redirect_uri):

        return "https://oauth.vk.com/authorize?" + parse.urlencode({
            "scope": "friends,offline",
            "client_id": app_id,
            "redirect_uri": redirect_uri,
            "response_type": "code"
        })

    def social_profile(self):
        return True

    def has_auth_form(self):
        return True
