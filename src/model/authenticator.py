import logging
import abc

from tornado.gen import coroutine, Return

import common.access
from common.model import Model

from password import UserNotFound, BadPassword, BadNameFormat


class Authenticator(Model):

    """
    An abstract class that able to prove that user owns the credential <credential>.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, application, credential_type):
        self.application = application
        self.credential_type = credential_type

    @abc.abstractmethod
    def authorize(self, gamespace, args, db=None, env=None):

        """
        Does the authorization. Returns `AuthenticationResult` instance.
        """

        raise NotImplementedError()

    @coroutine
    def get_key(self, gamespace, key_name):
        keys = self.application.keys
        key = yield keys.get_key_cached(gamespace, key_name, kv=self.application.cache)
        raise Return(key)

    def social_profile(self):
        """
        Whenever this authenticator has a social profile or not.
        """
        return False

    def type(self):
        return self.credential_type


class AuthoritativeAuthenticator(Authenticator):
    """
    Authenticator with a username/password record stored in a database.
    """
    def __init__(self, application, credential_type):
        super(AuthoritativeAuthenticator, self).__init__(application, credential_type)

    @coroutine
    def authorize(self, gamespace, args, db=None, env=None):
        try:
            credential, username, password = args["credential"], args["username"], args["key"]
        except KeyError:
            raise AuthenticationError("missing_argument")

        result = yield self.authorize_username_password(
            gamespace,
            credential,
            username,
            password,
            db=db)

        raise Return(result)

    @coroutine
    def authorize_username_password(self, gamespace, credential, username, password, db=None):
        passwords = self.application.passwords
        full_credential = credential + ":" + username

        try:
            yield passwords.login(full_credential, password, db)
        except BadPassword:
            raise AuthenticationError("bad_username_password")
        except BadNameFormat:
            raise AuthenticationError("bad_username_format")

        auth_result = AuthenticationResult(
            credential=credential,
            username=username,
            response=None)

        raise Return(auth_result)


class AccessTokenAuthenticator(AuthoritativeAuthenticator):
    """
    Authenticator by already existing token. All necessary data is extracted from `access_token`.

    """
    def __init__(self, application):
        super(AccessTokenAuthenticator, self).__init__(application, "token")

    @coroutine
    def authorize(self, gamespace, args, db=None, env=None):

        token_cache = self.application.token_cache

        if not token_cache:
            raise AuthenticationError("Token cache is not defined.", code=500)

        token_data = args["access_token"]
        token = common.access.AccessToken(token_data)

        valid = yield token_cache.validate(token)
        if valid:

            if gamespace != token.get(common.access.AccessToken.GAMESPACE):
                raise AuthenticationError("forbidden")

            full_credential = common.access.parse_account(token.name)
            credential = full_credential[0]
            username = full_credential[1]

            result = AuthenticationResult(
                credential=credential,
                username=username,
                response=None)

            raise Return(result)

        raise AuthenticationError("forbidden")


class AnonymousAuthenticator(AuthoritativeAuthenticator):
    """
    Anonymous. Authorization with non-existing account will create such.

    """
    def __init__(self, application):
        super(AnonymousAuthenticator, self).__init__(application, "anonymous")

    @coroutine
    def authorize(self, gamespace, args, db=None, env=None):
        try:
            result = yield AuthoritativeAuthenticator.authorize(
                self,
                gamespace,
                args,
                db=db)

            raise Return(result)
        except UserNotFound:

            try:
                yield self.register(args, db=db)
            except BadNameFormat:
                raise AuthenticationError("bad_username_format")

            # then try to authorise
            result = yield AuthoritativeAuthenticator.authorize(
                self,
                gamespace,
                args,
                db=db)

            raise Return(result)

    @coroutine
    def register(self, args, db=None):
        passwords = self.application.passwords

        credential, username, password = args["credential"], args["username"], args["key"]

        account_id = yield passwords.create(
            credential + ":" + username,
            password,
            db=db)

        raise Return(account_id)


class AuthenticationError(Exception):
    def __init__(self, message, code=None):
        self.message = message
        self.code = code


class AuthenticationResult:
    def __init__(self, credential, username, response):
        self.credential = credential
        self.username = username
        self.response = response


class DevAuthenticator(AuthoritativeAuthenticator):
    """
    Developer account. Pretty much like anonymous buy can be created only in an admin tool.
    """
    def __init__(self, application):
        super(DevAuthenticator, self).__init__(application, "dev")

    @coroutine
    def authorize(self, gamespace, args, db=None, env=None):
        try:
            result = yield AuthoritativeAuthenticator.authorize(
                self,
                gamespace,
                args,
                db=db,
                env=env)

        except UserNotFound:
            raise AuthenticationError("bad_username_password")
        else:
            raise Return(result)
