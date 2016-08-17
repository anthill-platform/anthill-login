
from tornado.gen import coroutine, Return
from common.options import options

import handler as h
import common.server
import common.handler
import common.access
import common.sign
import common.database
import common.keyvalue

from common.access import AccessToken

from model.password import PasswordsModel
from model.access import AccessModel
from model.token import AccessTokenModel
from model.credential import CredentialModel
from model.account import AccountModel
from model.gamespace import GamespacesModel
from model.key import KeyModel

import logging
import admin
import options as _opts


class AuthServer(common.server.Server):
    def __init__(self):
        super(AuthServer, self).__init__()

        self.db = common.database.Database(
            host=options.db_host,
            database=options.db_name,
            user=options.db_username,
            password=options.db_password)

        self.tokens = AccessTokenModel(self)

        self.cache = common.keyvalue.KeyValueStorage(
            host=options.cache_host,
            port=options.cache_port,
            db=options.cache_db,
            max_connections=options.cache_max_connections)

        self.keys = KeyModel(self.db)
        self.access = AccessModel(self.db)
        self.credentials = CredentialModel(self, self.db)
        self.accounts = AccountModel(self, self.db)
        self.passwords = PasswordsModel(self, self.db)
        self.gamespaces = GamespacesModel(self.db, [self.access, self.keys])

    @coroutine
    def started(self):
        yield self.tokens.start()
        yield super(AuthServer, self).started()

    def get_models(self):
        return [self.gamespaces, self.keys, self.accounts, self.access, self.credentials, self.passwords]

    def get_internal_handler(self):
        return h.InternalHandler(self)

    def get_metadata(self):
        return {
            "title": "Authorisation",
            "description": "Manage user accounts, credentials and access tokens",
            "icon": "key"
        }

    def get_admin(self):
        return {
            "index": admin.RootAdminController,
            "accounts": admin.AccountsController,
            "account": admin.EditAccountController,
            "invalidate_uuid": admin.InvalidateAccountUUIDController,
            "invalidate_all": admin.InvalidateAccountAllController,
            "credential": admin.EditCredentialController,
            "attach_credential": admin.AttachCredentialController,
            "authoritative": admin.AuthoritativeController,
            "edit_authoritative": admin.EditAuthoritativeController,
            "new_authoritative": admin.NewAuthoritativeController,
            "gamespaces": admin.GamespacesController,
            "gamespace": admin.GamespaceController,
            "new_gamespace": admin.NewGamespaceController,
            "new_gamespace_name": admin.NewGamespaceNameController,
            "gamespace_name": admin.GamespaceNameController,
            "keys": admin.KeysController,
            "new_key": admin.NewKeyController,
            "key": admin.KeyController,
            "edit_key": admin.EditKeyController
        }

    def get_handlers(self):
        return [
            (r"/logout", common.handler.LogoutHandler),
            (r"/authform", h.AuthAuthenticationHandler),
            (r"/authdev", h.AuthorizationDevHandler),

            (r"/attach", h.AttachAccountHandler),
            (r"/auth", h.AuthorizeHandler),
            (r"/resolve", h.ResolveConflictHandler),
            (r"/validate", h.ValidateHandler),
            (r"/extend", h.ExtendHandler)
        ]

    @coroutine
    def get_auth_location(self, network):
        raise Return(self.get_host())

    @coroutine
    def get_gamespace(self, gamespace_name):
        result = yield self.gamespaces.find_gamespace(gamespace_name)
        raise Return(result)


if __name__ == "__main__":

    stt = common.server.init()
    AccessToken.init([common.access.private()])
    common.server.start(AuthServer)
