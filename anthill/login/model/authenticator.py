
from anthill.common import access
from anthill.common.model import Model
from . password import UserNotFound, BadPassword, BadNameFormat
import abc


class Authenticator(Model, metaclass=abc.ABCMeta):

    """
    An abstract class that able to prove that user owns the credential <credential>.
    """

    def __init__(self, application, credential_type):
        self.application = application
        self.credential_type = credential_type

    @abc.abstractmethod
    def authorize(self, gamespace, args, db=None, env=None):

        """
        Does the authorization. Returns `AuthenticationResult` instance.
        """

        raise NotImplementedError()

    async def get_key(self, gamespace, key_name):
        keys = self.application.keys
        key = await keys.get_key_cached(gamespace, key_name, kv=self.application.cache)
        return key

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

    async def authorize(self, gamespace, args, db=None, env=None):
        try:
            credential, username, password = args["credential"], args["username"], args["key"]
        except KeyError:
            raise AuthenticationError("missing_argument")

        result = await self.authorize_username_password(
            gamespace,
            credential,
            username,
            password,
            db=db)

        return result

    async def authorize_username_password(self, gamespace, credential, username, password, db=None):
        passwords = self.application.passwords
        full_credential = credential + ":" + username

        try:
            await passwords.login(full_credential, password, db)
        except BadPassword:
            raise AuthenticationError("bad_username_password")
        except BadNameFormat:
            raise AuthenticationError("bad_username_format")

        auth_result = AuthenticationResult(
            credential=credential,
            username=username,
            response=None)

        return auth_result


class AccessTokenAuthenticator(AuthoritativeAuthenticator):
    """
    Authenticator by already existing token. All necessary data is extracted from `access_token`.

    """
    def __init__(self, application):
        super(AccessTokenAuthenticator, self).__init__(application, "token")

    async def authorize(self, gamespace, args, db=None, env=None):

        token_cache = self.application.token_cache

        if not token_cache:
            raise AuthenticationError("Token cache is not defined.", code=500)

        token_data = args["access_token"]
        token = access.AccessToken(token_data)

        valid = await token_cache.validate(token)
        if valid:

            if gamespace != token.get(access.AccessToken.GAMESPACE):
                raise AuthenticationError("forbidden")

            full_credential = access.parse_account(token.name)
            credential = full_credential[0]
            username = full_credential[1]

            result = AuthenticationResult(
                credential=credential,
                username=username,
                response=None)

            return result

        raise AuthenticationError("forbidden")


class AnonymousAuthenticator(AuthoritativeAuthenticator):
    """
    Anonymous. Authorization with non-existing account will create such.

    """
    def __init__(self, application):
        super(AnonymousAuthenticator, self).__init__(application, "anonymous")

    async def authorize(self, gamespace, args, db=None, env=None):
        try:
            result = await AuthoritativeAuthenticator.authorize(
                self,
                gamespace,
                args,
                db=db)

            return result
        except UserNotFound:

            try:
                await self.register(args, db=db)
            except BadNameFormat:
                raise AuthenticationError("bad_username_format")

            # then try to authorise
            result = await AuthoritativeAuthenticator.authorize(
                self,
                gamespace,
                args,
                db=db)

            return result

    async def register(self, args, db=None):
        passwords = self.application.passwords

        credential, username, password = args["credential"], args["username"], args["key"]

        account_id = await passwords.create(
            credential + ":" + username,
            password,
            db=db)

        return account_id


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

    async def authorize(self, gamespace, args, db=None, env=None):
        try:
            result = await AuthoritativeAuthenticator.authorize(
                self,
                gamespace,
                args,
                db=db,
                env=env)

        except UserNotFound:
            raise AuthenticationError("bad_username_password")
        else:
            return result
