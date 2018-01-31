import common.admin as a

import common.access
import datetime
import ujson

from tornado.gen import coroutine, Return
from common.social import apis

from model.access import UserInvalidError, ScopesCorrupterError, NoScopesFound
from model.password import UserExists, UserNotFound, BadNameFormat
from model.gamespace import GamespaceNotFound, GamespaceError, NoSuchGamespaceAlias
from model.credential import CredentialNotFound, CredentialIsNotValid, CredentialError
from model.key import KeyDataError, KeyNotFound



class AccountsController(a.AdminController):
    def render(self, data):
        return [
            a.breadcrumbs([], "Accounts"),
            a.split([
                a.form(title="Find by credential", fields={
                    "credential": a.field("User credential", "text", "primary", "non-empty"),
                }, methods={
                    "search_credential": a.method("Search", "primary")
                }, data=data),
                a.form(title="Find by account number", fields={
                    "account": a.field("Account number", "text", "primary", "number")
                }, methods={
                    "search_account": a.method("Search", "primary")
                }, data=data)
            ]),
            a.links("Navigate", [
                a.link("index", "Go back", icon="chevron-left")
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]

    @coroutine
    def search_account(self, account):
        raise a.Redirect("account", account=account)

    @coroutine
    def search_credential(self, credential):

        credentials = self.application.credentials

        try:
            account = yield credentials.get_account(credential)
        except CredentialNotFound:
            raise a.ActionError("No such credential")
        except (UserInvalidError, CredentialIsNotValid):
            raise a.ActionError("Credential format is invalid")

        raise a.Redirect("account", account=account)


class AttachCredentialController(a.AdminController):
    @coroutine
    def attach(self, credential):

        credentials = self.application.credentials
        account = self.context.get("account")

        try:
            test_id = yield credentials.get_account(credential)
        except CredentialNotFound:
            pass
        except (UserInvalidError, CredentialIsNotValid):
            raise a.ActionError("Credential format is invalid")
        else:
            if test_id != account:
                raise a.ActionError("This credential is already attached to another account (@{0}).".format(test_id), [
                    a.link("account", "Back (account @{0})".format(account), account=account),
                    a.link("account", "Edit conflicted account (@{0})".format(test_id), account=test_id)
                ])

        try:
            yield credentials.attach(credential, account)
        except (UserInvalidError, CredentialIsNotValid):
            raise a.ActionError("Credential format is invalid")

        raise a.Redirect("account", message="Account attached", account=account)

    def render(self, data):
        return [
            a.form(title="Attach a new credential to account #" + self.context.get("account"), fields={
                "credential": a.field("Credential", "text", "primary", "non-empty")
            }, methods={
                "attach": a.method("Attach", "primary")
            }, data=data),
            a.links("Navigate", [
                a.link("account", "Go back", icon="chevron-left", account=self.context.get("account"))
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]


class AuthoritativeController(a.AdminController):
    def render(self, data):
        return [
            a.breadcrumbs([], "Authoritative"),
            a.form(title="Enter username to edit", fields={
                "credential": a.field("User credential (dev:xxyy)", "text", "primary", "non-empty")
            }, methods={
                "search": a.method("Search", "primary")
            }, data=data),
            a.links("Navigate", [
                a.link("index", "Go back", icon="chevron-left"),
                a.link("new_authoritative", "New user", "plus")
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]

    @coroutine
    def search(self, credential):
        raise a.Redirect("edit_authoritative", credential=credential)


class EditAccountController(a.AdminController):
    @coroutine
    def get(self, account):
        access = self.application.access
        credentials = self.application.credentials

        gamespace_id = self.token.get(common.access.AccessToken.GAMESPACE)

        try:
            rights = yield access.get_account_access(gamespace_id, account)
        except NoScopesFound:
            rights = ""

        credential_list = yield credentials.list_account_credentials(account)

        result = {
            "rights": ",".join(rights),
            "credentials": credential_list
        }

        tokens = self.application.tokens
        uuids = yield tokens.get_uuids(account)

        result["tokens"] = {
            uuid: {
                "name": token["name"],
                "ttl": "{:0>8}".format(datetime.timedelta(seconds=token["ttl"]))
            }
            for uuid, token in uuids.iteritems()
        }

        raise a.Return(result)

    def render(self, data):

        f1 = a.form("Edit account (#" + str(self.context.get("account")) + ")", fields={
            "rights": a.field("Scope of access", "tags", "primary")
        }, methods={
            "update": a.method("Update", "primary")
        }, data=data)

        account = self.context.get("account")

        t1 = [
            a.link("invalidate_uuid", uuid, badge=token["name"], icon="tag", uuid=uuid, account=account)
            for uuid, token in data["tokens"].iteritems()
        ]

        if t1:
            t1.insert(0, a.link("invalidate_all", "Invalidate all", icon="remove", account=account))

        result = [
            a.breadcrumbs([
                a.link("accounts", "Accounts"),
            ], "Account @{0}".format(self.context.get("account"))),
            f1,
            a.links("Valid access tokens for this account. Click to invalidate.", t1)
        ]

        cr = a.links("Attached credentials", [
            a.link("credential", credential, "credit-card", credential=credential)
            for credential in data["credentials"]
        ])

        lnk = a.links("Navigate", [
            a.link("index", "Go back", icon="chevron-left"),
            a.link("/profile/profile", "Edit user profile", "link text-danger",
                   account=self.context.get("account")),
            a.link("attach_credential", "Attach a credential", "plus", account=self.context.get("account"))
        ])

        result.append(cr)
        result.append(lnk)

        return result

    def access_scopes(self):
        return ["auth_admin"]

    @coroutine
    def update(self, rights):

        account = self.get_context("account")

        access = self.application.access
        gamespace_id = self.token.get(common.access.AccessToken.GAMESPACE)

        try:
            yield access.set_account_access(gamespace_id, account, rights)
        except ScopesCorrupterError:
            raise a.ActionError("Scopes are corrupted")

        raise a.Redirect("account", message="Account updated", account=account)


class EditAuthoritativeController(a.AdminController):
    @coroutine
    def delete(self, password):
        credential = self.get_context("credential")

        passwords = self.application.passwords

        try:
            yield passwords.delete(credential)
        except UserNotFound:
            raise a.ActionError("No such user")

        raise a.Redirect("authoritative", message="User has been deleted")

    @coroutine
    def get(self, credential):

        passwords = self.application.passwords

        try:
            user = yield passwords.get(credential)
        except BadNameFormat:
            raise a.ActionError("Bad user format")
        except UserNotFound:
            raise a.ActionError("No such user")

        result = {
            "user": user,
            "credential": credential
        }

        raise a.Return(result)

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("authoritative", "Authoritative"),
            ], "Account {0}".format(self.context.get("credential"))),
            a.form("Edit authoritative: " + data["credential"], fields={
                "password": a.field("Password", "text", "primary")
            }, methods={
                "update": a.method("Update", "primary"),
                "delete": a.method("Delete credential", "danger")
            }, data=data),
            a.links("Navigate", [
                a.link("index", "Go back", icon="chevron-left"),
                a.link("new_authoritative", "New user", "plus")
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]

    @coroutine
    def update(self, password):
        credential = self.get_context("credential")

        passwords = self.application.passwords

        try:
            yield passwords.update(credential, password)
        except UserNotFound:
            raise a.ActionError("No such user")

        raise a.Redirect("edit_authoritative", message="User has been updated", credential=credential)


class EditCredentialController(a.AdminController):
    @coroutine
    def delete(self):

        credential = self.context.get("credential")
        credentials = self.application.credentials

        try:
            account = yield credentials.get_account(credential)
        except CredentialNotFound:
            raise a.ActionError("No such credential")
        except (UserInvalidError, CredentialIsNotValid):
            raise a.ActionError("Credential format is invalid")

        try:
            credentials.detach(credential, account)
        except CredentialError as e:
            raise a.ActionError(e.message)

        raise a.Redirect("account", message="Credential has been updated", account=account)

    @coroutine
    def migrate_credential(self, moveto):

        credentials = self.application.credentials
        credential = self.context.get("credential")

        try:
            account = yield credentials.get_account(credential)
        except CredentialNotFound:
            raise a.ActionError("No such credential")
        except (UserInvalidError, CredentialIsNotValid):
            raise a.ActionError("Credential format is invalid")

        try:
            moveto = yield credentials.get_account(moveto)
        except CredentialNotFound:
            raise a.ActionError("No such credential")
        except (UserInvalidError, CredentialIsNotValid):
            raise a.ActionError("Credential format is invalid")

        try:
            credentials.detach(credential, account)
            credentials.attach(credential, moveto)
        except CredentialError as e:
            raise a.ActionError(e.message)

        raise a.Redirect("account",
                         message="Credential has been migrated",
                         account=moveto)

    @coroutine
    def migrate_account(self, moveto):

        credentials = self.application.credentials
        credential = self.context.get("credential")

        moveto = common.to_int(moveto)

        try:
            account = yield credentials.get_account(credential)
        except CredentialNotFound:
            raise a.ActionError("No such credential")
        except (UserInvalidError, CredentialIsNotValid):
            raise a.ActionError("Credential format is invalid")

        try:
            credentials.detach(credential, account)
            credentials.attach(credential, moveto)
        except CredentialError as e:
            raise a.ActionError(e.message)

        raise a.Redirect("account",
                         message="Credential has been migrated",
                         account=moveto)

    @coroutine
    def get(self, credential):

        credentials = self.application.credentials

        try:
            account = yield credentials.get_account(credential)
        except CredentialNotFound:
            raise a.ActionError("No such credential")
        except (UserInvalidError, CredentialIsNotValid):
            raise a.ActionError("Credential format is invalid")

        result = {
            "account": account
        }

        raise a.Return(result)

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("accounts", "Accounts"),
                a.link("account", "Account @{0}".format(data["account"]),
                       account=data["account"])
            ], self.context.get("credential")),
            a.form("Detach credential <b>{0}</b> from account <b>@{1}</b>".format(
                self.context.get("credential"),
                data["account"],
            ), fields={}, methods={
                "delete": a.method("Detach", "danger")
            }, icon="exclamation-triangle", data=data),
            a.split([
                a.form("Move credential to another account", fields={
                    "moveto": a.field("Account ID (for example 123)", "text", "primary", "number")
                }, methods={
                    "migrate_account": a.method("Migrate", "primary")
                }, icon="plane", data=data),
                a.form("Move credential to another account by credential", fields={
                    "moveto": a.field("Credential (for example dev:test01)", "text", "primary", "non-empty")
                }, methods={
                    "migrate_credential": a.method("Migrate", "primary")
                }, icon="plane", data=data),
            ]),
            a.links("Navigate", [
                a.link("account", "Go back", icon="chevron-left", account=data["account"])
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]


class EditKeyController(a.AdminController):
    @coroutine
    def get(self, key_id):
        keys = self.application.keys

        try:
            key = yield keys.get_key(self.gamespace, key_id)
        except KeyNotFound:
            raise a.ActionError("No such key")

        key_name = key.name

        try:
            key_data = yield keys.get_key_decoded(self.gamespace, key_id)
        except KeyNotFound:
            raise a.ActionError("No such key")

        api_type = apis.api_types.get(key_name)
        if api_type:
            api = api_type(self.application.cache)

            if api.has_private_key():
                private_key = yield api.get_private_key(self.gamespace, data=key_data)

                if private_key.has_ui():
                    private_key_data = private_key.get()

                    raise a.Return({
                        "key_name": key_name,
                        "private_key": private_key,
                        "private_key_data": private_key_data
                    })

        raise a.Return({
            "key_name": key_name,
            "key_data": key_data
        })

    def render(self, data):

        r = [
            a.breadcrumbs([
                a.link("keys", "Keys"),
                a.link("key", data["key_name"], key_id=self.context.get("key_id"))
            ], "Edit contents")
        ]

        private_key = data.get("private_key")

        if private_key:
            r.append(a.form(data["key_name"], fields=private_key.render(), methods={
                "update_api_key": a.method("Update Key", "primary")
            }, data=data["private_key_data"]))
        else:
            r.append(a.form(data["key_name"], fields={
                "key_data": a.field("Key Data", "json", "primary", "non-empty", multiline=8, order=2)
            }, methods={
                "update_raw_key": a.method("Update Key", "primary")
            }, data=data))

        r.append(a.links("Navigate", [
                a.link("keys", "Go back", icon="chevron-left")
        ]))

        return r

    def access_scopes(self):
        return ["auth_admin"]

    @coroutine
    def update_api_key(self, **kwargs):
        keys = self.application.keys

        key_id = self.context.get("key_id")

        try:
            key = yield keys.get_key(self.gamespace, key_id)
        except KeyNotFound:
            raise a.ActionError("No such key")

        key_name = key.name
        api_type = apis.api_types.get(key_name)

        if not api_type:
            raise a.ActionError("No such type of key: {0}".format(key_name))

        api = api_type(self.application.cache)

        if not api.has_private_key():
            raise a.ActionError("This type of key is not supported")

        try:
            key_data = yield keys.get_key_decoded(self.gamespace, key_id)
        except KeyNotFound:
            raise a.ActionError("No such key")

        private_key = yield api.get_private_key(self.gamespace, data=key_data)
        private_key.update(**kwargs)
        new_data = private_key.dump()

        try:
            yield keys.update_key_data(self.gamespace, key_id, new_data)
        except KeyDataError as e:
            raise a.ActionError("Failed to update a key: " + e.message)

        raise a.Redirect("key",
                         message="Key has been updated",
                         key_id=key_id)

    @coroutine
    def update_raw_key(self, key_data):

        try:
            key_data = ujson.loads(key_data)
        except (KeyError, ValueError):
            raise a.ActionError("Corrupted key.")

        keys = self.application.keys
        key_id = self.context.get("key_id")

        try:
            yield keys.update_key_data(self.gamespace, key_id, key_data)
        except KeyDataError as e:
            raise a.ActionError("Failed to update a key: " + e.message)

        raise a.Redirect("edit_key",
                         message="Key has been updated",
                         key_id=key_id)


class GamespaceController(a.AdminController):
    @coroutine
    def delete(self):

        gamespaces_data = self.application.gamespaces
        gamespace = self.context.get("gamespace")

        try:
            yield gamespaces_data.delete_gamespace(gamespace)
        except GamespaceError as g:
            raise a.ActionError(g.message)

        raise a.Redirect("gamespaces", message="Gamespace has been deleted")

    @coroutine
    def get(self, gamespace):

        gamespaces_data = self.application.gamespaces

        try:
            gamespace_data = yield gamespaces_data.get_gamespace(gamespace)
        except GamespaceNotFound:
            raise a.ActionError("No such gamespace")
        except GamespaceError as e:
            raise a.ActionError("Failed to get a gamespace: " + e.message)

        try:
            names = yield gamespaces_data.list_gamespace_aliases(gamespace)
        except GamespaceError as e:
            raise a.ActionError("Failed to get a gamespace names: " + e.message)

        result = {
            "title": gamespace_data.title,
            "scopes": gamespace_data.scopes,
            "names": names
        }

        raise a.Return(result)

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("gamespaces", "Gamespaces"),
            ], data["title"]),
            a.form("Edit gamespace", fields={
                "title": a.field("Gamespace title (For administration purposes):",
                                 "text", "primary", "non-empty", order=1),
                "scopes": a.field("Default access:", "tags", "primary", order=2, placeholder="A list of scopes")
            }, methods={
                "update": a.method("Update", "primary")
            }, data=data),
            a.links("Gamespace authorization names", [
                a.link("gamespace_name", name.name, icon="at", record_id=name.record_id)
                for name in data["names"]
            ] + [
                a.link("new_gamespace_name", "Add new name", icon="plus", gamespace=self.context.get("gamespace"))
            ]),
            a.form("Danger zone", fields={
                "well": a.field("Deleting the gamespace is dangerous: you WILL lost all you data related to it.",
                                "notice", "danger")
            }, methods={
                "delete": a.method("Delete this gamespace", "danger", doublecheck="Yes, delete this gamespace")
            }, data=data),
            a.links("Navigate", [
                a.link("index", "Go back", icon="chevron-left"),
                a.link("new_gamespace", "New gamespace", "plus")
            ])
        ]

    def access_scopes(self):
        return ["auth_gamespace_admin"]

    @coroutine
    def update(self, title, scopes):

        gamespaces_data = self.application.gamespaces
        gamespace = self.context.get("gamespace")

        scopes = common.access.parse_scopes(scopes)

        try:
            yield gamespaces_data.update_gamespace(gamespace, title, scopes)
        except GamespaceError as g:
            raise a.ActionError(g.message)

        raise a.Redirect("gamespace", message="Gamespace has been updated", gamespace=gamespace)


class GamespaceNameController(a.AdminController):
    @coroutine
    def delete(self, **ignored):

        gamespaces_data = self.application.gamespaces
        record_id = self.context.get("record_id")

        try:
            name = yield gamespaces_data.get_gamespace_alias(record_id)
        except NoSuchGamespaceAlias:
            raise a.ActionError("No such gamespace name")

        try:
            yield gamespaces_data.delete_gamespace_alias(record_id)
        except GamespaceError as g:
            raise a.ActionError(g.message)

        raise a.Redirect("gamespace", message="Name has been deleted", gamespace=name.gamespace_id)

    @coroutine
    def get(self, record_id):

        gamespaces_data = self.application.gamespaces

        try:
            name = yield gamespaces_data.get_gamespace_alias(record_id)
        except NoSuchGamespaceAlias:
            raise a.ActionError("No such gamespace name")

        gamespace = name.gamespace_id

        try:
            gamespace_data = yield gamespaces_data.get_gamespace(gamespace)
        except GamespaceNotFound:
            raise a.ActionError("No such gamespace")
        except GamespaceError as e:
            raise a.ActionError("Failed to get a gamespace: " + e.message)

        try:
            gamespaces = yield gamespaces_data.list_gamespaces()
        except GamespaceError as e:
            raise a.ActionError(e.message)

        result = {
            "name": name.name,
            "gamespaces": {
                gs.gamespace_id: gs.title
                for gs in gamespaces
            },
            "gamespace": gamespace,
            "gamespace_data": gamespace_data
        }

        raise a.Return(result)

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("gamespaces", "Gamespaces"),
                a.link("gamespace", data["gamespace_data"].title, gamespace=data["gamespace"]),
            ], data["name"]),
            a.form("Edit gamespace name", fields={
                "name": a.field("Gamespace name:", "text", "primary", "non-empty", order=1),
                "gamespace": a.field(
                    "Gamespace this name attached to:", "select", "primary", "non-empty",
                    order=2, values=data["gamespaces"]),
            }, methods={
                "update": a.method("Update", "primary", order=1),
                "delete": a.method("Delete", "danger", order=2)
            }, data=data),
            a.links("Navigate", [
                a.link("gamespace", "Go back", icon="chevron-left", gamespace=data["gamespace"]),
                a.link("new_gamespace_name", "New gamespace name", "plus", gamespace=data["gamespace"])
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]

    @coroutine
    def update(self, name, gamespace):

        gamespaces_data = self.application.gamespaces
        record_id = self.context.get("record_id")

        try:
            yield gamespaces_data.get_gamespace_alias(record_id)
        except NoSuchGamespaceAlias:
            raise a.ActionError("No such gamespace name")

        try:
            yield gamespaces_data.update_gamespace_name(record_id, name, gamespace)
        except GamespaceError as g:
            raise a.ActionError(g.message)

        raise a.Redirect("gamespace_name", message="Name has been updated", record_id=record_id)


class GamespacesController(a.AdminController):
    @coroutine
    def get(self):
        gamespaces_data = self.application.gamespaces
        gamespaces = yield gamespaces_data.list_gamespaces()

        result = {
            "gamespaces": gamespaces
        }

        raise a.Return(result)

    def render(self, data):
        return [
            a.breadcrumbs([], "Gamespaces"),
            a.links("Select gamespace", links=[
                a.link("gamespace", g.title, "folder-o", gamespace=g.gamespace_id) for g in data["gamespaces"]
            ]),
            a.links("Navigate", [
                a.link("index", "Go back", icon="chevron-left"),
                a.link("new_gamespace", "New gamespace", "plus")
            ])
        ]

    def access_scopes(self):
        return ["auth_gamespace_admin"]


class InvalidateAccountAllController(a.AdminController):
    @coroutine
    def get(self, account):
        tokens = self.application.tokens

        if (yield tokens.invalidate_account(account)):
            raise a.Redirect("account", message="Tokens have been invalidated", account=account)

        raise a.ActionError("Unknown account")

    def access_scopes(self):
        return ["auth_admin"]

class InvalidateAccountUUIDController(a.AdminController):
    @coroutine
    def get(self, uuid, account):
        tokens = self.application.tokens

        if (yield tokens.invalidate_uuid(account, uuid)):
            raise a.Redirect("account", message="Token has been invalidated", account=account)

        raise a.ActionError("Unknown UUID")

    def access_scopes(self):
        return ["auth_admin"]


class KeyController(a.AdminController):
    @coroutine
    def delete(self, **ignored):
        keys = self.application.keys
        key_id = self.context.get("key_id")

        try:
            yield keys.delete_key(self.gamespace, key_id)
        except KeyDataError as e:
            raise a.ActionError("Failed to delete a key: " + e.message)

        raise a.Redirect("keys", message="Key has been deleted")

    @coroutine
    def edit(self, **ignored):
        key_id = self.context.get("key_id")

        raise a.Redirect("edit_key", key_id=key_id)

    @coroutine
    def get(self, key_id):
        keys = self.application.keys

        try:
            key = yield keys.get_key(self.gamespace, key_id)
        except KeyNotFound:
            raise a.ActionError("No such key")

        raise a.Return({
            "key_name": key.name
        })

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("keys", "Keys")
            ], data["key_name"]),

            a.form("Key", fields={
                "key_name": a.field("Key Name", "text", "primary", "non-empty", order=1),
            }, methods={
                "update": a.method("Update Key", "primary"),
                "delete": a.method("Delete Key", "danger"),
            }, data=data),

            a.form("Key contents is encrypted. You may edit it here.", fields={}, methods={
                "edit": a.method("See / Edit Contents", "danger",
                                 danger="Are you sure you want to see / edit this key?")
            }, data=data),

            a.links("Navigate", [
                a.link("keys", "Go back", icon="chevron-left")
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]

    @coroutine
    def update(self, key_name):

        keys = self.application.keys
        key_id = self.context.get("key_id")

        try:
            yield keys.update_key(self.gamespace, key_id, key_name)
        except KeyDataError as e:
            raise a.ActionError("Failed to create a key: " + e.message)

        raise a.Redirect("key", message="Key has been updated", key_id=key_id)


class KeysController(a.AdminController):
    @coroutine
    def get(self):

        keys = self.application.keys

        key_list = yield keys.list_keys(self.gamespace)

        raise a.Return({
            "keys": key_list
        })

    def render(self, data):
        return [
            a.breadcrumbs([], "Keys"),
            a.links("List of keys", [
                a.link("key", key.name, icon="key", key_id=key.key_id)
                for key in data["keys"]
            ]),
            a.links("Navigate", [
                a.link("index", "Go back", icon="chevron-left"),
                a.link("new_api_key", "Add new key", icon="plus"),
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]


class NewAuthoritativeController(a.AdminController):
    @coroutine
    def create(self, credential, password):

        passwords = self.application.passwords

        try:
            yield passwords.create(credential, password)
        except UserExists:
            raise a.ActionError("Such user already exists")
        except BadNameFormat:
            raise a.ActionError("Bad username format, should be (dev|anonymous):[a-z, A-Z, 0-9, _] only")

        raise a.Redirect("edit_authoritative", message="New user has been created", credential=credential)

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("authoritative", "Authoritative"),
            ], "New account"),
            a.form("New authoritative credential", fields={
                "credential": a.field("Username (dev:xxxyy)", "text", "primary", "non-empty"),
                "password": a.field("Password", "text", "primary", "non-empty")
            }, methods={
                "create": a.method("Create", "primary")
            }, data=data),
            a.links("Navigate", [
                a.link("index", "Go back", icon="chevron-left")
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]


class NewGamespaceController(a.AdminController):
    @coroutine
    def create(self, title, scopes):

        gamespaces_data = self.application.gamespaces

        scopes = common.access.parse_scopes(scopes)

        try:
            gamespace = yield gamespaces_data.create_gamespace(title, scopes)
        except GamespaceError as g:
            raise a.ActionError(g.message)

        raise a.Redirect("gamespace", message="New gamespace has been created", gamespace=gamespace)

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("gamespaces", "Gamespaces"),
            ], "New gamespace"),
            a.notice("Notice",
                     """
                     Please make sure you're doing this for a reason.
                     Creating a new gamespace consumes new unique ID across the whole system.
                     Deleting this gamespace later will result in abandoned records (users, profiles, etc)
                     related to this gamespace.
                     """),
            a.form("Create new gamespace", fields={
                "title": a.field("Gamespace title (For administration purposes):",
                                 "text", "primary", "non-empty", order=1),
                "scopes": a.field("Default access:", "tags", "primary", order=2, placeholder="A list of scopes")
            }, methods={
                "create": a.method("Create a new gamespace", "primary")
            }, data=data),
            a.links("Navigate", [
                a.link("gamespaces", "Go back", icon="chevron-left")
            ])
        ]

    def access_scopes(self):
        return ["auth_gamespace_admin"]


class NewGamespaceNameController(a.AdminController):
    @coroutine
    def create(self, name):
        gamespace = self.context.get("gamespace")

        gamespaces_data = self.application.gamespaces

        try:
            yield gamespaces_data.get_gamespace(gamespace)
        except GamespaceNotFound:
            raise a.ActionError("No such gamespace")
        except GamespaceError as e:
            raise a.ActionError("Failed to get a gamespace: " + e.message)

        try:
            yield gamespaces_data.create_gamespace_alias(name, gamespace_id=gamespace)
        except GamespaceError as e:
            raise a.ActionError("Failed to add a gamespace name: " + e.message)

        raise a.Redirect("gamespace", message="New name has been created", gamespace=gamespace)

    @coroutine
    def get(self, gamespace):

        gamespaces_data = self.application.gamespaces

        try:
            gamespace_data = yield gamespaces_data.get_gamespace(gamespace)
        except GamespaceNotFound:
            raise a.ActionError("No such gamespace")
        except GamespaceError as e:
            raise a.ActionError("Failed to get a gamespace: " + e.message)

        raise Return({
            "gamespace_title": gamespace_data.title
        })

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("gamespaces", "Gamespaces"),
                a.link("gamespace", data["gamespace_title"], gamespace=self.context.get("gamespace"))
            ], "New name"),
            a.form("Create new gamespace name", fields={
                "name": a.field("Gamespace name:", "text", "primary", "non-empty", order=1)
            }, methods={
                "create": a.method("Create a new name", "primary")
            }, data=data),
            a.links("Navigate", [
                a.link("gamespace", "Go back", icon="chevron-left", gamespace=self.context.get("gamespace"))
            ])
        ]

    def access_scopes(self):
        return ["auth_gamespace_admin"]


class NewRawKeyController(a.AdminController):

    @coroutine
    def get(self):
        raise Return({
            "key_data": {}
        })

    @coroutine
    def create(self, key_name, key_data):

        try:
            key_data = ujson.loads(key_data)
        except (KeyError, ValueError):
            raise a.ActionError("Corrupted JSON.")

        keys = self.application.keys

        try:
            key_id = yield keys.add_key(self.gamespace, key_name, key_data)
        except KeyDataError as e:
            raise a.ActionError("Failed to create a key: " + e.message)

        raise a.Redirect("key", message="New key has been created", key_id=key_id)

    def render(self, data):
        return [
            a.breadcrumbs([
                a.link("keys", "Keys")
            ], "New raw key"),

            a.form("Add new raw key", fields={
                "key_name": a.field("Key Name", "text", "primary", "non-empty", order=1),
                "key_data": a.field("Key Data, will be encrypted", "json", "primary", "non-empty", multiline=8, order=2)
            }, methods={
                "create": a.method("Create new Key", "primary")
            }, data=data),

            a.links("Navigate", [
                a.link("keys", "Go back", icon="chevron-left")
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]


class NewAPIKeyController(a.AdminController):

    @coroutine
    def get(self):
        key_types = {
            api_type_name: api_type_name
            for api_type_name, api_type in apis.api_types.iteritems()
        }

        raise Return({
            "key_types": key_types
        })

    @coroutine
    def proceed(self, key_type):
        keys = self.application.keys

        api_types = apis.api_types
        api_type = api_types.get(key_type)

        if not api_type:
            raise a.ActionError("No such key type")

        api = api_type(self.application.cache)

        if not api.has_private_key():
            raise a.ActionError("Bad kay type")

        try:
            key = yield keys.find_key(self.gamespace, key_type)
        except KeyDataError as e:
            raise a.ActionError("Failed to lookup a key: " + e.message)
        except KeyNotFound as e:
            pass
        else:
            raise a.Redirect("key", message="This key already exists", key_id=key.key_id)

        private_key = api.new_private_key(None)

        raise Return({
            "private_key": private_key,
            "key_type": key_type,
            "private_key_data": {}
        })

    @coroutine
    def create(self, **kwargs):

        keys = self.application.keys

        key_type = self.context.get("key_type")

        api_types = apis.api_types
        api_type = api_types.get(key_type)

        if not api_type:
            raise a.ActionError("No such key type")

        api = api_type(self.application.cache)

        if not api.has_private_key():
            raise a.ActionError("Bad kay type")

        private_key = api.new_private_key(None)
        private_key.update(**kwargs)

        key_data = private_key.dump()

        try:
            key_id = yield keys.add_key(self.gamespace, key_type, key_data)
        except KeyDataError as e:
            raise a.ActionError("Failed to create a key: " + e.message)

        raise a.Redirect("key", message="New key has been created", key_id=key_id)

    def render(self, data):

        r = [
            a.breadcrumbs([
                a.link("keys", "Keys")
            ], "New API key")
        ]

        private_key = data.get("private_key")

        if private_key:
            key_type = data.get("key_type")

            r.append(a.form("New key: {0}".format(key_type), fields=private_key.render(), methods={
                "create": a.method("Create", "primary")
            }, data=private_key.get(), key_type=key_type))
        else:
            r.append(a.form("Select the key type", fields={
                "key_type": a.field("Key Type", "select", "primary", "non-empty", order=1, values=data["key_types"]),
            }, methods={
                "proceed": a.method("Proceed", "primary")
            }, data=data))

        r.append(a.links("Navigate", [
            a.link("keys", "Go back", icon="chevron-left"),
            a.link("new_raw_key", "Create a raw key", icon="plus"),
        ]))

        return r

    def access_scopes(self):
        return ["auth_admin"]


class RootAdminController(a.AdminController):
    def render(self, data):
        return [
            a.links("Authorisation service", [
                a.link("accounts", "Edit accounts", icon="lock"),
                a.link("authoritative", "Edit authoritative credentials", icon="user"),
                a.link("gamespaces", "Edit gamespaces", icon="folder-o"),
                a.link("keys", "Edit keys", icon="key"),
            ])
        ]

    def access_scopes(self):
        return ["auth_admin"]
