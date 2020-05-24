
from anthill.common import access
from anthill.common.database import DatabaseError
from anthill.common.model import Model


class NoScopesFound(Exception):
    pass


class ScopesCorrupterError(Exception):
    pass


class AccessModel(Model):
    """
    A model representing a simple role: to clarify whenever an account has some scopes of access or not.
    """

    def __init__(self, db):
        self.db = db

    def get_setup_tables(self):
        return ["account_access"]

    async def setup_table_account_access(self):
        await self.set_account_access(1, 1, "admin,auth_admin,discovery_admin,profile_admin,social_admin,"
                                            "config_admin,store_admin,event_admin,game_admin,dlc_admin,"
                                            "message_admin,env_envs_admin,env_admin,leaderboard_admin,"
                                            "exec_admin,auth_gamespace_admin,game_deploy_admin,auth_gamespace_admin,"
                                            "static_admin,promo_admin,report_admin,admin_audit_log,"
                                            "game_host")

    def get_setup_db(self):
        return self.db

    async def get_account_access(self, gamespace_id, account_id, db=None):
        """
        Gets a list of access scopes for an account inside a gamespace.
        :return: A list of scopes.
        """

        try:
            user = await (db or self.db).get("""
                SELECT `scopes`
                FROM `account_access`
                WHERE `account_id`=%s AND `gamespace_id`=%s;
            """, account_id, gamespace_id)
        except DatabaseError as e:
            raise AccessError("Failed to get account access: " + e.args[1])

        if user is None:
            raise NoScopesFound()

        return access.parse_scopes(user['scopes'])

    async def set_account_access(self, gamespace_id, account_id, access_scopes, db=None):
        """
        Sets a list of scopes for an account inside a gamespace.
        :param gamespace_id: gamespace ID
        :param account_id: account ID
        :param access_scopes: A comma-separated list of scopes
        """

        scopes = access.parse_scopes(access_scopes)
        if scopes is None:
            raise ScopesCorrupterError()

        scopes_res = access.serialize_scopes(scopes)

        try:
            await self.get_account_access(gamespace_id, account_id, db=db)
        except NoScopesFound:
            try:
                result = await (db or self.db).insert("""
                    INSERT INTO `account_access`
                    (`account_id`, `gamespace_id`, `scopes`)
                    VALUES (%s, %s, %s);
                """, account_id, gamespace_id, scopes_res)
            except DatabaseError as e:
                raise AccessError("Failed to insert account access: " + e.args[1])
        else:
            try:
                result = await (db or self.db).execute("""
                    UPDATE `account_access`
                    SET `scopes`=%s
                    WHERE `account_id`=%s AND `gamespace_id`=%s;
                """, scopes_res, account_id, gamespace_id)
            except DatabaseError as e:
                raise AccessError("Failed to update account access: " + e.args[1])

        return result

    async def delete_gamespace(self, gamespace_id, db=None):

        """
        NEVER CALL THAT
        """
        try:
            await (db or self.db).execute("""
                DELETE FROM `account_access`
                WHERE `gamespace_id`=%s;
            """, gamespace_id)
        except DatabaseError as e:
            raise AccessError("Failed to delete account access: " + e.args[1])


class UserInvalidError(Exception):
    pass


class AccessError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message
