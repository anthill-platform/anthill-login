import urllib
import urlparse
import base64
import logging
import ujson

from tornado.web import HTTPError
from tornado.gen import coroutine, Return

import common.access
import common.sign

from common.internal import InternalError
from common.access import scoped, internal
from common.handler import AuthenticatedHandler, AnthillRequestHandler, JsonHandler
from common.validate import validate_value, ValidationError

from model.access import ScopesCorrupterError, NoScopesFound
from model.account import AuthenticationError
from model.gamespace import GamespaceNotFound
from model.credential import CredentialNotFound, CredentialIsNotValid, CredentialError
from model.key import KeyNotFound, KeyDataError
from model.token import TokensError, AccessToken
from model.password import UserExists, BadNameFormat

from social import SocialAuthenticator
from social import google, facebook, vk


class AttachAccountHandler(JsonHandler):
    """
    Attaches a credential to an account.
    """

    def data_received(self, chunk):
        pass

    @coroutine
    def post(self):
        arguments = {
            key: value[0]
            for key, value in self.request.arguments.iteritems()
        }

        try:
            env = ujson.loads(self.get_argument("env", "{}"))
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted env")

        remote_ip = common.access.remote_ip(self.request)
        if remote_ip:
            env["ip_address"] = remote_ip

        accounts_data = self.application.accounts

        try:
            result = yield accounts_data.attach_account(arguments, env=env)

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

    @coroutine
    def post(self):
        arguments = {
            key: value[0]
            for key, value in self.request.arguments.iteritems()
        }

        accounts_data = self.application.accounts

        try:
            env = ujson.loads(self.get_argument("env", "{}"))
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted env")

        remote_ip = common.access.remote_ip(self.request)
        if remote_ip:
            env["ip_address"] = remote_ip

        try:
            # proceeds the authorization
            result = yield accounts_data.authorize(arguments, env)

            if self.get_argument("full", False) == "true":
                self.dumps(result)
            else:
                self.write(result["token"])

        except KeyError as e:
            raise HTTPError(
                400,
                "Missing mandatory fields")

        except AuthenticationError as e:
            self.result(e.code, e.obj)

    def result(self, code, obj):
        self.set_status(code, "result")
        self.dumps(obj)


class AuthAuthenticationHandler(AuthenticatedHandler):
    """
    Render authorization web form.
    """

    @coroutine
    def get(self):

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

        remote_ip = common.access.remote_ip(self.request)
        if remote_ip:
            env["ip_address"] = remote_ip

        try:
            gamespace_id = yield gamespaces.find_gamespace(gamespace_name)
        except GamespaceNotFound:
            raise HTTPError(404, "No such gamespace")

        if self.current_user:
            token = self.current_user.token
            if token.is_valid():
                try:
                    new_token = yield self.application.accounts.authorize({
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

                    url_parts = list(urlparse.urlparse(redirect_to))

                    query = dict(urlparse.parse_qsl(url_parts[4]))
                    query.update({
                        "token": encoded_token
                    })

                    url_parts[4] = urllib.urlencode(query)

                    self.redirect(urlparse.urlunparse(url_parts))

                    return

        social_apis = [
            name
            for name, authorizer in credential_types.iteritems()
            if isinstance(authorizer, SocialAuthenticator)
        ]

        checked_social_apis = yield keys.check_keys(gamespace_id, social_apis)

        scopes = common.access.parse_scopes(scopes_data)

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
    @coroutine
    def get(self, credential_type):

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
            gamespace_id = yield gamespaces.find_gamespace(gamespace_name)
        except GamespaceNotFound:
            raise HTTPError(404, "No such gamespace")

        try:
            client_id = yield api.get_app_id(gamespace=gamespace_id)
        except KeyNotFound:
            raise HTTPError(500, "This auth is not configured yet")

        url = api.generate_login_url(client_id, redirect_uri)

        self.redirect(url)


class ExtendHandler(AuthenticatedHandler):
    """
    Extend access token rights with right of the another access token.
    """
    @scoped()
    @coroutine
    def post(self):
        extend, scopes = self.get_argument("extend"), self.get_argument("scopes", "*")

        extend_token = common.access.AccessToken(extend)
        token_cache = self.application.token_cache

        if not token_cache:
            raise HTTPError(500, "Token cache is not defined.")

        valid = yield token_cache.validate(extend_token)
        if not valid:
            raise HTTPError(
                403,
                "Token extend to is not valid")

        tokens = self.application.tokens

        try:
            new_data = yield tokens.extend(
                self.token,
                extend_token,
                scopes)

        except TokensError as e:
            raise HTTPError(403, e.message)

        self.dumps({
            "token": new_data["key"],
            "expires_in": new_data["expires"],
            "scopes": new_data["scopes"],
            "account": new_data["account"]
        })


class AuthorizationDevHandler(AuthenticatedHandler):
    """
    Renders developer authorization form.
    """

    @coroutine
    def get(self):
        self.render("template/authdev.html")


class InternalHandler(object):
    def __init__(self, application):
        self.application = application

    @coroutine
    def check_account_exists(self, account):
        accounts = self.application.accounts
        exists = yield accounts.check_account_exists(account)

        raise Return({
            "exists": exists
        })

    @coroutine
    def extend_token(self, token, extend_with, scopes="*"):

        token = common.access.AccessToken(token)
        extend_with = common.access.AccessToken(extend_with)
        token_cache = self.application.token_cache

        if not token_cache:
            raise HTTPError(500, "Token cache is not defined.")

        if not (yield token_cache.validate(token)):
            raise InternalError(403, "Token extend to is not valid")
        if not (yield token_cache.validate(extend_with)):
            raise InternalError(403, "Token extend with to is not valid")
        tokens = self.application.tokens

        try:
            new_data = yield tokens.extend(token, extend_with, scopes)
        except TokensError as e:
            raise InternalError(403, e.message)

        new_token_string = new_data["key"]

        raise Return({
            "access_token": new_token_string,
            "expires_in": new_data["expires"],
            "scopes": new_data["scopes"]
        })

    @coroutine
    def get_scopes(self, credential, gamespace):
        credentials = self.application.credentials
        gamespaces = self.application.gamespaces
        access = self.application.access

        try:
            gamespace = yield gamespaces.find_gamespace_info(gamespace)
        except GamespaceNotFound:
            raise InternalError(404, "Gamespace '{0}' was not found".format(gamespace))
        else:
            gamespace_id = gamespace.gamespace_id

        try:
            account_id = yield credentials.get_account(credential)
        except CredentialNotFound:
            raise InternalError(404, "No such credential")
        except CredentialIsNotValid:
            raise InternalError(400, "Bad credential")

        try:
            account_scopes = yield access.get_account_access(gamespace_id, account_id)
        except NoScopesFound:
            raise InternalError(404, "User has no scopes")

        raise Return({
            "scopes": ",".join(account_scopes)
        })

    @coroutine
    def set_scopes(self, credential, gamespace, scopes):
        credentials = self.application.credentials
        gamespaces = self.application.gamespaces
        access = self.application.access

        try:
            gamespace = yield gamespaces.find_gamespace_info(gamespace)
        except GamespaceNotFound:
            raise InternalError(404, "Gamespace '{0}' was not found".format(gamespace))
        else:
            gamespace_id = gamespace.gamespace_id

        try:
            account_id = yield credentials.get_account(credential)
        except CredentialNotFound:
            raise InternalError(404, "No such credential")
        except CredentialIsNotValid:
            raise InternalError(400, "Bad credential")

        yield access.set_account_access(gamespace_id, account_id, scopes)

        raise Return("OK")

    @coroutine
    def get_account(self, credential):
        credentials = self.application.credentials

        try:
            account_id = yield credentials.get_account(credential)
        except CredentialNotFound:
            raise InternalError(404, "No such credential")
        except CredentialIsNotValid:
            raise InternalError(400, "Bad credential")
        else:
            raise Return({
                "id": account_id
            })

    @coroutine
    def get_credential(self, credential_type, account_id):
        credentials = self.application.credentials

        try:
            credentials = yield credentials.list_account_credentials(
                account_id, credential_types=[credential_type])
        except CredentialError as e:
            raise InternalError(e.code, e.message)
        else:
            if not credentials:
                raise InternalError(404, "No such credentials for such account")

            raise Return({
                "credential": credentials[0]
            })

    @coroutine
    def new_gamespace(self, name):

        gamespaces = self.application.gamespaces

        try:
            yield gamespaces.find_gamespace_info(name)
        except GamespaceNotFound:
            gamespace_id = yield gamespaces.create_gamespace(name, [])
            yield gamespaces.create_gamespace_alias(name, gamespace_id)
            raise Return("OK")
        else:
            raise InternalError(404, "Such gamespace already exists")

    @coroutine
    def new_dev_credential(self, username, password):

        passwords = self.application.passwords

        try:
            account_id = yield passwords.create(username, password)
        except UserExists:
            raise InternalError(400, "Such user exists")
        except BadNameFormat:
            raise InternalError(400, "Bad name format")

        raise Return({
            "account": account_id
        })

    @coroutine
    def get_gamespace(self, name):

        gamespaces = self.application.gamespaces

        try:
            gamespace = yield gamespaces.find_gamespace_info(name)
        except GamespaceNotFound:
            raise InternalError(404, "Gamespace '{0}' was not found".format(name))
        else:
            raise Return({
                "id": gamespace.gamespace_id,
                "name": name,
                "title": gamespace.title
            })

    @coroutine
    def get_gamespaces(self):

        gamespaces_data = self.application.gamespaces
        gamespaces = yield gamespaces_data.list_all_aliases()
        result = [
            {
                "name": alias.name,
                "id": alias.gamespace_id
            }
            for alias in gamespaces
        ]

        raise Return(result)

    @coroutine
    def get_key(self, gamespace, key_name):
        keys = self.application.keys
        try:
            key = yield keys.get_key_cached(gamespace, key_name, kv=self.application.cache)
        except KeyNotFound:
            raise InternalError(404, "No such key")
        except KeyDataError as e:
            raise InternalError(500, e.message)
        else:
            raise Return(key)

    @coroutine
    def refresh_token(self, access_token):
        token = common.access.AccessToken(access_token)
        tokens = self.application.tokens

        try:
            new_data = yield tokens.refresh(token)
        except TokensError as e:
            raise InternalError(403, e)

        new_token_string = new_data["key"]

        raise Return({
            "access_token": new_token_string
        })

    @coroutine
    def validate_token(self, access_token):

        token = common.access.AccessToken(access_token)

        if (yield self.application.tokens.validate(token)):
            raise Return({
                "result": "ok"
            })
        else:
            raise InternalError(
                403, "Token is not valid.")

    @coroutine
    def authenticate(self, env=None, **kwargs):
        try:
            token = yield self.application.accounts.authorize(kwargs, env=env)
        except KeyError:
            raise InternalError(400, "Missing fields")
        except AuthenticationError as e:
            raise InternalError(e.code, ujson.dumps(e.obj))
        else:
            raise Return(token)


class ResolveConflictHandler(AuthenticatedHandler):
    """
    Resolves conflicts.
    """

    def data_received(self, chunk):
        pass

    @scoped(scopes=["resolve_conflict"])
    @coroutine
    def post(self):
        resolve_method = self.get_argument("resolve_method")

        # get POST arguments into a dict
        arguments = {
            key: value[0]
            for key, value in self.request.arguments.iteritems()
        }

        try:
            env = ujson.loads(self.get_argument("env", "{}"))
        except (KeyError, ValueError):
            raise HTTPError(400, "Corrupted env")

        remote_ip = common.access.remote_ip(self.request)
        if remote_ip:
            env["ip_address"] = remote_ip

        accounts_data = self.application.accounts

        try:
            result = yield accounts_data.resolve_conflict(self.token, resolve_method, arguments, env=env)

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
    @coroutine
    def get(self):
        token_string = self.get_argument("access_token")

        token = common.access.AccessToken(token_string)

        if (yield self.application.tokens.validate(token)):
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
    @coroutine
    @scoped()
    def get(self):

        credentials = self.application.credentials

        try:
            user_credentials = yield credentials.list_account_credentials(self.token.account)
        except CredentialError as e:
            raise HTTPError(e.code, e.message)

        self.dumps({
            "credentials": user_credentials,
            "account_id": self.token.account
        })


class AccountIDSByCredentialsHandler(AuthenticatedHandler):
    @scoped()
    @coroutine
    def get(self):
        credentials = self.application.credentials
        credentials_data = self.get_argument("credentials")

        try:
            credentials_data = ujson.loads(credentials_data)
            credentials_data = validate_value(credentials_data, "json_list_of_strings")
        except (KeyError, ValueError, ValidationError):
            raise HTTPError(400, "Corrupted credentials")

        try:
            account_ids = yield credentials.list_accounts_by_credentials(credentials_data)
        except CredentialError as e:
            raise HTTPError(e.code, e.message)

        self.dumps({
            "account_ids": account_ids
        })
