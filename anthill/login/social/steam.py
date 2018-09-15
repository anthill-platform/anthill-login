
from .. model.authenticator import AuthenticationResult, AuthenticationError
from . import SocialAuthenticator

import logging

from anthill.common.social import APIError
from anthill.common.social.apis import SteamAPI


CREDENTIAL_TYPE = "steam"


class SteamAuthenticator(SocialAuthenticator, SteamAPI):
    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, SteamAPI.NAME)
        SteamAPI.__init__(self, None)

    async def authorize(self, gamespace, args, db=None, env=None):
        try:
            ticket = args["ticket"]
            app_id = args["app_id"]
        except KeyError:
            raise AuthenticationError("missing_argument")

        try:
            result = await self.api_auth(gamespace, ticket, app_id)
        except APIError as e:
            logging.exception("api error")
            raise AuthenticationError("API error:" + e.body, e.code)
        else:
            auth_result = AuthenticationResult(credential=self.type(),
                                               username=result.username,
                                               response=result)

            return auth_result

    def social_profile(self):
        return True
