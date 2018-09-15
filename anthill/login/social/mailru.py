
from tornado.httpclient import HTTPError

from .. model.authenticator import AuthenticationResult, AuthenticationError
from .. model.key import KeyNotFound
from . import SocialAuthenticator

import logging
from urllib import parse

from anthill.common.social import APIError
from anthill.common.social.apis import MailRuAPI


CREDENTIAL_TYPE = "mailru"


class MailRuAuthenticator(SocialAuthenticator, MailRuAPI):
    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, MailRuAPI.NAME)
        MailRuAPI.__init__(self, None)

    async def authorize_mailru_api(self, gamespace, args, db=None, env=None):
        try:
            uid = args["uid"]
            hash = args["hash"]
        except KeyError:
            logging.error("Missing arguments")
            raise AuthenticationError("missing_argument")

        ip_address = env.get("ip_address", None) if env else None

        if not ip_address:
            raise AuthenticationError("ip_address required")

        private_key = await self.get_private_key(gamespace)

        sign = self.calculate_signature({
            "appid": private_key.get_mailru_app_id(),
            "ip": ip_address,
            "hash": hash,
            "uid": uid
        }, private_key)

        gas_url = MailRuAPI.MAILRU_API + private_key.mailru_app_id + "/gas?" + parse.urlencode({
            "uid": uid,
            "hash": hash,
            "ip": ip_address,
            "sign": sign
        })

        try:
            self.client.fetch(gas_url)
        except HTTPError:
            raise AuthenticationError("forbidden")

        auth_result = AuthenticationResult(credential=self.type(),
                                           username=uid,
                                           response=None)

        return auth_result

    async def authorize_steam_api(self, gamespace, args, db=None, env=None):
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

    def authorize(self, gamespace, args, db=None, env=None):
        """
        This method can perform two ways of authentication
          - The mailru one, if "uid" and "hash" arguments are present
          - The steam one, if "ticket" and "app_id" arguments are present
        """
        if "uid" in args and "hash" in args:
            return self.authorize_mailru_api(gamespace, args, db=db, env=env)
        if "ticket" in args and "app_id" in args:
            return self.authorize_steam_api(gamespace, args, db=db, env=env)
        raise AuthenticationError("missing_argument")

    # noinspection PyMethodMayBeStatic
    def social_profile(self):
        return True
