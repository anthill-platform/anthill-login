
import logging
import urllib

import tornado.httpclient
from tornado.gen import coroutine, Return

from common.social.apis import MailRuAPI
from model import authenticator
from model.authenticator import AuthenticationResult
from . import SocialAuthenticator


class MailRuAuthenticator(SocialAuthenticator, MailRuAPI):

    GAMES_ROOT_URL = "https://games.mail.ru/app/"
    TYPE = "mailru"

    def __init__(self, application):
        SocialAuthenticator.__init__(self, application, MailRuAuthenticator.TYPE)
        MailRuAPI.__init__(self, None)

    @coroutine
    def authorize(self, gamespace, args, db=None, env=None):
        try:
            uid = args["uid"]
            hash = args["hash"]
        except KeyError:
            logging.error("Missing arguments")
            raise authenticator.AuthenticationError("missing_argument")

        ip_address = env.get("ip_address", None) if env else None

        if not ip_address:
            raise authenticator.AuthenticationError("ip_address required")

        private_key = yield self.get_private_key(gamespace)

        sign = self.calculate_signature({
            "appid": private_key.app_id,
            "ip": ip_address,
            "hash": hash,
            "uid": uid
        }, private_key)

        gas_url = MailRuAuthenticator.GAMES_ROOT_URL + private_key.app_id + "/gas?" + urllib.urlencode({
            "uid": uid,
            "hash": hash,
            "ip": ip_address,
            "sign": sign
        })

        try:
            self.client.fetch(gas_url)
        except tornado.httpclient.HTTPError:
            raise authenticator.AuthenticationError("forbidden")

        auth_result = AuthenticationResult(credential=self.type(),
                                           username=uid,
                                           response=None)

        raise Return(auth_result)

    def social_profile(self):
        return True
