
from anthill.common import access
from anthill.common.database import DatabaseError
from anthill.common.model import Model

from . import authenticator

import logging


class CredentialNotFound(Exception):
    pass


class CredentialError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def __str__(self):
        return str(self.code) + ": " + self.message


class CredentialModel(Model):
    """
    A model to represent user credential. To add new credential type, please see `init` method.

    Credential is just a way for user to authorize. After that user works with account.
    """
    def __init__(self, application, db):
        self.db = db
        self.credential_types = {}

        self.init(application)

    def get_setup_tables(self):
        return ["account_credentials"]

    async def setup_table_account_credentials(self):
        await self.attach("dev:root", 1)

    def get_setup_db(self):
        return self.db

    async def attach(self, credential, account, db=None):
        """
        Attaches a credential to an account.
        """

        if not access.parse_account(credential):
            raise CredentialIsNotValid()

        try:
            await (db or self.db).insert(
                """
                    INSERT INTO `account_credentials`
                    (`credential`, `account_id`)
                    VALUES (%s, %s);
                """, credential, account)
        except DatabaseError as e:
            raise CredentialError(500, "Failed to create credential: " + e.args[1])

        logging.info("Account attached '%s'->'%s'.", credential, account)

    async def detach(self, credential, account, accounts_data=None, db=None):
        """
        Detaches a credential from account.
        :param credential: A credential
        :param account: An account
        :param accounts_data: AccountModel instance to delete account if credential has no account attached to left.
        :param db: A database instance
        :return: Whenever user have credentials left in an account <account>
        """

        try:
            await (db or self.db).execute(
                """
                    DELETE FROM `account_credentials`
                    WHERE `credential`=%s AND `account_id`=%s;
                """, credential, account)
        except DatabaseError as e:
            raise CredentialError(500, "Failed to detach credential: " + e.args[1])

        logging.info("Account detached '%s' from '%s'.", credential, account)

        account_credentials = await self.list_account_credentials(account, db=db)

        have_credentials = bool(account_credentials)

        if (not have_credentials) and accounts_data:
            logging.info("Account deleted '%s'.", account)
            await accounts_data.delete_account(account, db=db)

        return have_credentials

    async def list_accounts(self, credential, db=None):
        """
        Return accounts have this credential attached.
        """

        try:
            result = await (db or self.db).query(
                """
                    SELECT `account_id`
                    FROM `account_credentials`
                    WHERE `credential`=%s;
                """, credential)
        except DatabaseError as e:
            raise CredentialError(500, "Failed to list accounts: " + e.args[1])

        return [str(r["account_id"]) for r in result]

    async def list_account_credentials(self, account_id, credential_types=None, db=None):
        """
        List all credentials, attached to an account.
        :param account_id: An account
        :param credential_types: A filter of credential types to return.
        :param db: a db
        :return: A list of credentials.
        """

        try:
            result = await (db or self.db).query(
                """
                    SELECT `credential`
                    FROM `account_credentials`
                    WHERE `account_id`=%s;
                """, account_id)
        except DatabaseError as e:
            raise CredentialError(500, "Failed to list credentials: " + e.args[1])

        if credential_types:
            def _check(c_):
                parsed = access.parse_account(c_["credential"])
                return (parsed[0] in credential_types) if parsed else False

            result = [c["credential"] for c in result if _check(c)]
        else:
            result = [c["credential"] for c in result]

        return result

    async def list_accounts_by_credentials(self, credentials, db=None, amount_max=500):
        if not credentials:
            return []

        if len(credentials) > amount_max:
            raise CredentialError(413, "Too many credentials being asked for")

        try:
            result = await (db or self.db).query(
                """
                    SELECT `account_id`
                    FROM `account_credentials`
                    WHERE `credential` IN %s;
                """, credentials)
        except DatabaseError as e:
            raise CredentialError(500, "Failed to get accounts: " + e.args[1])

        result = [r['account_id'] for r in result]

        return result

    async def get_account(self, credential, db=None):
        """
        Looks an account for a credential. If there is no such, does nothing.
        """
        if not access.parse_account(credential):
            raise CredentialIsNotValid()

        try:
            result = await (db or self.db).get(
                """
                    SELECT `account_id`
                    FROM `account_credentials`
                    WHERE `credential`=%s;
                """, credential)
        except DatabaseError as e:
            raise CredentialError(500, "Failed to get account: " + e.args[1])

        if result is None:
            raise CredentialNotFound()

        return str(result["account_id"]) if "account_id" in result else None

    def init(self, application):

        from .. social import google
        from .. social import facebook
        from .. social import gamecenter
        from .. social import steam
        from .. social import vk
        from .. social import mailru

        self.register(authenticator.DevAuthenticator(application))
        self.register(google.GoogleAuthenticator(application))
        self.register(vk.VKAuthenticator(application))
        self.register(facebook.FacebookAuthenticator(application))
        self.register(mailru.MailRuAuthenticator(application))
        self.register(gamecenter.GameCenterAuthorizer(application))
        self.register(steam.SteamAuthenticator(application))
        self.register(authenticator.AnonymousAuthenticator(application))
        self.register(authenticator.AccessTokenAuthenticator(application))

    def register(self, auth, credential=None):
        if credential is None:
            credential = auth.type()

        self.credential_types[credential] = auth


class CredentialIsNotValid(Exception):
    pass
