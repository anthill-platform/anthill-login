
from tornado.web import HTTPError

from anthill.common import access

from anthill.common.internal import InternalError
from anthill.common.access import scoped, AccessToken
from anthill.common.handler import AuthenticatedHandler, AnthillRequestHandler, JsonHandler
from anthill.common.validate import validate_value, ValidationError

from . model.access import NoScopesFound
from . model.account import AuthenticationError
from . model.gamespace import GamespaceNotFound
from . model.credential import CredentialNotFound, CredentialIsNotValid, CredentialError
from . model.key import KeyNotFound, KeyDataError
from . model.token import TokensError
from . model.password import UserExists, BadNameFormat

from . social import SocialAuthenticator
from . social import google, facebook, vk

from urllib import parse
import base64
import logging
import ujson


class AttachAccountHandler(JsonHandler):
    """
    Attaches a credential to an account.
    """

    def data_received(self, chunk):
        pass

    async def post(self):
        arguments = {
            key: value[0]
            for key, value in self.request.arguments.items()
        }

        try:
            env = ujson.loads(self.get_argument("env", "{}"))
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted env")

        remote_ip = access.remote_ip(self.request)
        if remote_ip:
            env["ip_address"] = remote_ip

        accounts_data = self.application.accounts

        try:
            result = await accounts_data.attach_account(arguments, env=env)

            if self.get_argument("full", False) == "true":
                self.dumps(result)
            else:
                self.write(result["token"])

        except KeyError:
            raise HTTPError(
                400,
                "Missing mandatory fields")

        except AuthenticationError as e:
            logging.exception(
                "Failed to auth: {0} {1}".format(
                    e.code, ujson.dumps(e.obj)))

            self.result(e.code, e.obj)

    def result(self, code, obj):
        self.set_status(code, "result")
        self.dumps(obj)


class AuthorizeHandler(JsonHandler):
    """
    Authorizes the user.
    """

    def data_received(self, chunk):
        pass

    async def post(self):
        arguments = {
            key: value[0].decode("utf-8")
            for key, value in self.request.arguments.items()
        }

        accounts_data = self.application.accounts

        try:
            env = ujson.loads(self.get_argument("env", "{}"))
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted env")

        remote_ip = access.remote_ip(self.request)
        if remote_ip:
            env["ip_address"] = remote_ip

        try:
            # proceeds the authorization
            result = await accounts_data.authorize(arguments, env)

            if self.get_argument("full", False) == "true":
                self.dumps(result)
            else:
                self.write(result["token"])

        except KeyError as e:
            raise HTTPError(
                400,
                "Missing mandatory field: " + str(e))

        except AuthenticationError as e:
            self.result(e.code, e.obj)

    def result(self, code, obj):
        self.set_status(code, "result")
        self.dumps(obj)


class AuthAuthenticationHandler(AuthenticatedHandler):
    """
    Render authorization web form.
    """

    async def get(self):

        credential_types = self.application.credentials.credential_types
        gamespaces = self.application.gamespaces
        keys = self.application.keys

        auth_as = self.get_argument("as", None)
        gamespace_name = self.get_argument('gamespace')
        redirect_to = self.get_argument('redirect')
        should_have = self.get_argument("should_have", "*")
        scopes_data = self.get_argument('scopes')
        attach_to = self.get_argument("attach_to", None)

        try:
            env = ujson.loads(self.get_argument("env", "{}"))
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted env")

        remote_ip = access.remote_ip(self.request)
        if remote_ip:
            env["ip_address"] = remote_ip

        try:
            gamespace_id = await gamespaces.find_gamespace(gamespace_name)
        except GamespaceNotFound:
            raise HTTPError(404, "No such gamespace")

        if self.current_user:
            token = self.current_user.token
            if token.is_valid():
                try:
                    new_token = await self.application.accounts.authorize({
                        "credential": "token",
                        "access_token": token.key,
                        "gamespace": gamespace_name,
                        "scopes": scopes_data,
                        "should_have": should_have,
                        "as": auth_as
                    }, env=env)
                except AuthenticationError:
                    logging.error("Failed to pre-authenticate user in login page.")

                else:
                    encoded_token = base64.b64encode(new_token["token"])

                    url_parts = list(parse.urlparse(redirect_to))

                    query = dict(parse.parse_qsl(url_parts[4]))
                    query.update({
                        "token": encoded_token
                    })

                    url_parts[4] = parse.urlencode(query)

                    self.redirect(parse.urlunparse(url_parts))

                    return

        social_apis = [
            name
            for name, authorizer in credential_types.items()
            if isinstance(authorizer, SocialAuthenticator)
        ]

        checked_social_apis = await keys.check_keys(gamespace_id, social_apis)

        scopes = access.parse_scopes(scopes_data)

        self.render(
            "template/form.html",

            scopes=scopes,
            redirect_to=redirect_to,
            social_apis=checked_social_apis,
            should_have=should_have,
            gamespace=gamespace_name,
            attach_to=attach_to,
            auth_as=auth_as)


class OAuth2CallbackHandler(AnthillRequestHandler):
    def get(self):
        self.render("template/callback.html")


class SocialAuthAuthenticationFormHandler(AuthenticatedHandler):
    async def get(self, credential_type):

        credential_types = self.application.credentials.credential_types
        gamespaces = self.application.gamespaces

        gamespace_name = self.get_argument('gamespace')
        redirect_uri = self.get_argument('redirect', self.get_argument("redirect_uri"))

        try:
            api = credential_types[credential_type]
        except KeyError:
            raise HTTPError(400, "Not supported")

        if not api.has_auth_form():
            raise HTTPError(400, "Not supported")

        try:
            gamespace_id = await gamespaces.find_gamespace(gamespace_name)
        except GamespaceNotFound:
            raise HTTPError(404, "No such gamespace")

        try:
            client_id = await api.get_app_id(gamespace=gamespace_id)
        except KeyNotFound:
            raise HTTPError(500, "This auth is not configured yet")

        url = api.generate_login_url(client_id, redirect_uri)

        self.redirect(url)


class ExtendHandler(AuthenticatedHandler):
    """
    Extend access token rights with right of the another access token.
    """
    @scoped()
    async def post(self):
        extend, scopes = self.get_argument("extend"), self.get_argument("scopes", "*")

        extend_token = access.AccessToken(extend)
        token_cache = self.application.token_cache

        if not token_cache:
            raise HTTPError(500, "Token cache is not defined.")

        valid = await token_cache.validate(extend_token)
        if not valid:
            raise HTTPError(
                403,
                "Token extend to is not valid")

        tokens = self.application.tokens

        try:
            new_data = await tokens.extend(
                self.token,
                extend_token,
                scopes)

        except TokensError as e:
            raise HTTPError(403, e.message)

        self.dumps({
            "token": new_data["key"],
            "expires_in": new_data["expires"],
            "scopes": new_data["scopes"],
            "account": new_data["account"],
            "credential": new_data.get("credential")
        })


class AuthorizationDevHandler(AuthenticatedHandler):
    """
    Renders developer authorization form.
    """

    async def get(self):
        self.render("template/authdev.html")


class InternalHandler(object):
    def __init__(self, application):
        self.application = application

    async def check_account_exists(self, account):
        accounts = self.application.accounts
        exists = await accounts.check_account_exists(account)

        return {
            "exists": exists
        }

    async def extend_token(self, token, extend_with, scopes="*"):

        token = access.AccessToken(token)
        extend_with = access.AccessToken(extend_with)
        token_cache = self.application.token_cache

        if not token_cache:
            raise HTTPError(500, "Token cache is not defined.")

        if not (await token_cache.validate(token)):
            raise InternalError(403, "Token extend to is not valid")
        if not (await token_cache.validate(extend_with)):
            raise InternalError(403, "Token extend with to is not valid")
        tokens = self.application.tokens

        try:
            new_data = await tokens.extend(token, extend_with, scopes)
        except TokensError as e:
            raise InternalError(403, e.message)

        new_token_string = new_data["key"]

        return {
            "access_token": new_token_string,
            "expires_in": new_data["expires"],
            "scopes": new_data["scopes"]
        }

    async def get_scopes(self, credential, gamespace):
        credentials = self.application.credentials
        gamespaces = self.application.gamespaces
        app_access = self.application.access

        try:
            gamespace = await gamespaces.find_gamespace_info(gamespace)
        except GamespaceNotFound:
            raise InternalError(404, "Gamespace '{0}' was not found".format(gamespace))
        else:
            gamespace_id = gamespace.gamespace_id

        try:
            account_id = await credentials.get_account(credential)
        except CredentialNotFound:
            raise InternalError(404, "No such credential")
        except CredentialIsNotValid:
            raise InternalError(400, "Bad credential")

        try:
            account_scopes = await app_access.get_account_access(gamespace_id, account_id)
        except NoScopesFound:
            raise InternalError(404, "User has no scopes")

        return {
            "scopes": ",".join(account_scopes)
        }

    async def set_scopes(self, credential, gamespace, scopes):
        credentials = self.application.credentials
        gamespaces = self.application.gamespaces
        app_access = self.application.access

        try:
            gamespace = await gamespaces.find_gamespace_info(gamespace)
        except GamespaceNotFound:
            raise InternalError(404, "Gamespace '{0}' was not found".format(gamespace))
        else:
            gamespace_id = gamespace.gamespace_id

        try:
            account_id = await credentials.get_account(credential)
        except CredentialNotFound:
            raise InternalError(404, "No such credential")
        except CredentialIsNotValid:
            raise InternalError(400, "Bad credential")

        await app_access.set_account_access(gamespace_id, account_id, scopes)

        return "OK"

    async def get_account(self, credential):
        credentials = self.application.credentials

        try:
            account_id = await credentials.get_account(credential)
        except CredentialNotFound:
            raise InternalError(404, "No such credential")
        except CredentialIsNotValid:
            raise InternalError(400, "Bad credential")
        else:
            return {
                "id": account_id
            }

    async def get_credential(self, credential_type, account_id):
        credentials = self.application.credentials

        try:
            credentials = await credentials.list_account_credentials(
                account_id, credential_types=[credential_type])
        except CredentialError as e:
            raise InternalError(e.code, e.message)
        else:
            if not credentials:
                raise InternalError(404, "No such credentials for such account")

            return {
                "credential": credentials[0]
            }

    async def new_gamespace(self, name):

        gamespaces = self.application.gamespaces

        try:
            await gamespaces.find_gamespace_info(name)
        except GamespaceNotFound:
            gamespace_id = await gamespaces.create_gamespace(name, [])
            await gamespaces.create_gamespace_alias(name, gamespace_id)
            return "OK"
        else:
            raise InternalError(404, "Such gamespace already exists")

    async def new_dev_credential(self, username, password):

        passwords = self.application.passwords

        try:
            account_id = await passwords.create(username, password)
        except UserExists:
            raise InternalError(400, "Such user exists")
        except BadNameFormat:
            raise InternalError(400, "Bad name format")

        return {
            "account": account_id
        }

    async def get_gamespace(self, name):

        gamespaces = self.application.gamespaces

        try:
            gamespace = await gamespaces.find_gamespace_info(name)
        except GamespaceNotFound:
            raise InternalError(404, "Gamespace '{0}' was not found".format(name))
        else:
            return {
                "id": gamespace.gamespace_id,
                "name": name,
                "title": gamespace.title
            }

    async def get_gamespaces(self):

        gamespaces_data = self.application.gamespaces
        gamespaces = await gamespaces_data.list_all_aliases()
        result = [
            {
                "name": alias.name,
                "id": alias.gamespace_id
            }
            for alias in gamespaces
        ]

        return result

    async def get_key(self, gamespace, key_name):
        keys = self.application.keys
        try:
            key = await keys.get_key_cached(gamespace, key_name, kv=self.application.cache)
        except KeyNotFound:
            raise InternalError(404, "No such key")
        except KeyDataError as e:
            raise InternalError(500, e.message)
        else:
            return key

    async def refresh_token(self, access_token):
        token = access.AccessToken(access_token)
        tokens = self.application.tokens

        try:
            new_data = await tokens.refresh(token)
        except TokensError as e:
            raise InternalError(403, e)

        new_token_string = new_data["key"]

        return {
            "access_token": new_token_string
        }

    async def validate_token(self, access_token):
        token = access.AccessToken(access_token)

        if await self.application.tokens.validate(token):
            return {
                "result": "ok"
            }
        else:
            raise InternalError(
                403, "Token is not valid.")

    async def authenticate(self, env=None, **kwargs):
        try:
            token = await self.application.accounts.authorize(kwargs, env=env)
        except KeyError:
            raise InternalError(400, "Missing fields")
        except AuthenticationError as e:
            raise InternalError(e.code, ujson.dumps(e.obj))
        else:
            return token


class ResolveConflictHandler(AuthenticatedHandler):
    """
    Resolves conflicts.
    """

    def data_received(self, chunk):
        pass

    @scoped(scopes=["resolve_conflict"])
    async def post(self):
        resolve_method = self.get_argument("resolve_method")

        # get POST arguments into a dict
        arguments = {
            key: value[0]
            for key, value in self.request.arguments.items()
        }

        try:
            env = ujson.loads(self.get_argument("env", "{}"))
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted env")

        remote_ip = access.remote_ip(self.request)
        if remote_ip:
            env["ip_address"] = remote_ip

        accounts_data = self.application.accounts

        try:
            result = await accounts_data.resolve_conflict(self.token, resolve_method, arguments, env=env)

            if self.get_argument("full", False) == "true":
                self.dumps(result)
            else:
                self.write(result["token"])

        except KeyError:
            raise HTTPError(
                400, "Missing mandatory fields")

        except AuthenticationError as e:
            logging.exception("Failed to resolve: ")
            self.result(e.code, e.obj)

    def result(self, code, obj):
        self.set_status(code, "result")
        self.dumps(obj)


class ValidateHandler(JsonHandler):
    async def get(self):
        token_string = self.get_argument("access_token")

        token = access.AccessToken(token_string)

        if await self.application.tokens.validate(token):
            self.dumps({
                "account": str(token.account),
                "credential": token.get(AccessToken.USERNAME),
                "scopes": token.scopes
            })
        else:
            raise HTTPError(
                403,
                "Token is not valid.")


class AccountCredentialsHandler(AuthenticatedHandler):
    @scoped()
    async def get(self):

        credentials = self.application.credentials

        try:
            user_credentials = await credentials.list_account_credentials(self.token.account)
        except CredentialError as e:
            raise HTTPError(e.code, e.message)

        self.dumps({
            "credentials": user_credentials,
            "account_id": self.token.account
        })


class AccountIDSByCredentialsHandler(AuthenticatedHandler):
    @scoped()
    async def get(self):
        credentials = self.application.credentials
        credentials_data = self.get_argument("credentials")

        try:
            credentials_data = ujson.loads(credentials_data)
            credentials_data = validate_value(credentials_data, "json_list_of_strings")
        except (KeyError, ValueError, ValidationError):
            raise HTTPError(400, "Corrupted credentials")

        try:
            account_ids = await credentials.list_accounts_by_credentials(credentials_data)
        except CredentialError as e:
            raise HTTPError(e.code, e.message)

        self.dumps({
            "account_ids": account_ids
        })
