import re

from tornado.gen import coroutine, Return

import common.access
from common.database import DatabaseError
from common.model import Model


class GamespaceAdapter(object):
    def __init__(self, data):
        self.gamespace_id = data.get("gamespace_id")
        self.scopes = data.get("gamespace_scopes")
        self.title = data.get("gamespace_title")


class GamespaceAliasAdapter(object):
    def __init__(self, data):
        self.gamespace_id = data.get("gamespace_id")
        self.name = data["gamespace_name"]
        self.record_id = data["record_id"]


class GamespaceError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class GamespaceNotFound(Exception):
    pass


class GamespacesModel(Model):
    """
    A model representing a gamespace.

    Gamespace is an unique game ID that divides game-related data from other games.
    For example, a account1 may have profile in gamespace1, but in gamespace2 the same account will have
        different profile.

    """
    def __init__(self, db, dependencies):
        self.db = db
        self.dependencies = dependencies

    def get_setup_tables(self):
        return ["gamespace", "gamespace_aliases"]

    def get_setup_db(self):
        return self.db

    @coroutine
    def setup_table_gamespace(self):
        yield self.create_gamespace(
            "Default",
            ["profile_write", "profile", "game", "message_listen", "group", "party", "event", "exec_func_call"])

    @coroutine
    def setup_table_gamespace_aliases(self):
        yield self.create_gamespace_alias("root", 1)

    @coroutine
    def delete_gamespace(self, gamespace_id, db=None):

        for dependency in self.dependencies:
            yield dependency.delete_gamespace(gamespace_id)

        try:
            yield (db or self.db).query(
                """
                    DELETE FROM `gamespace_aliases`
                    WHERE `gamespace_id`=%s;
                """, gamespace_id)

            yield (db or self.db).query(
                """
                    DELETE FROM `gamespace`
                    WHERE `gamespace_id`=%s;
                """, gamespace_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to delete a gamespace: " + e.args[1])

    @coroutine
    def delete_gamespace_alias(self, record_id, db=None):
        try:
            yield (db or self.db).query(
                """
                    DELETE FROM `gamespace_aliases`
                    WHERE `record_id`=%s;
                """, record_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to delete a gamespace name: " + e.args[1])

    @coroutine
    def find_gamespace(self, gamespace_name, db=None):
        try:
            gamespace = yield (db or self.db).get(
                """
                    SELECT `gamespace_id`
                    FROM `gamespace_aliases`
                    WHERE `gamespace_name`=%s;
                """, gamespace_name)
        except DatabaseError as e:
            raise GamespaceError("Failed to get a gamespace: " + e.args[1])

        if gamespace is None:
            raise GamespaceNotFound()

        raise Return(str(gamespace["gamespace_id"]))

    @coroutine
    def find_gamespace_info(self, gamespace_alias, db=None):
        try:
            gamespace = yield (db or self.db).get(
                """
                    SELECT n.`gamespace_id`, g.`gamespace_title`
                    FROM `gamespace_aliases` AS n
                    LEFT JOIN `gamespace` AS g
                        ON g.`gamespace_id` = n.`gamespace_id`
                    WHERE n.`gamespace_name`=%s;
                """, gamespace_alias)
        except DatabaseError as e:
            raise GamespaceError("Failed to find a gamespace info: " + e.args[1])

        if gamespace is None:
            raise GamespaceNotFound()

        raise Return(GamespaceAdapter(gamespace))

    @coroutine
    def find_gamespace_alias(self, name, db=None):
        try:
            alias = yield (db or self.db).get(
                """
                    SELECT *
                    FROM `gamespace_aliases`
                    WHERE `gamespace_name`=%s;
                """, name)
        except DatabaseError as e:
            raise GamespaceError("Failed to find an alias: " + e.args[1])

        if alias is None:
            raise NoSuchGamespaceAlias()

        raise Return(GamespaceAliasAdapter(alias))

    @coroutine
    def get_gamespace(self, gamespace_id, db=None):
        try:
            gamespace = yield (db or self.db).get(
                """
                    SELECT *
                    FROM `gamespace`
                    WHERE `gamespace_id`=%s;
                """, gamespace_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to get a gamespace: " + e.args[1])

        if gamespace is None:
            raise GamespaceNotFound()

        raise Return(GamespaceAdapter(gamespace))

    @coroutine
    def get_gamespace_alias(self, record_id, db=None):
        try:
            alias = yield (db or self.db).get(
                """
                    SELECT *
                    FROM `gamespace_aliases`
                    WHERE `record_id`=%s;
                """, record_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to get an alias: " + e.args[1])

        if alias is None:
            raise NoSuchGamespaceAlias()

        raise Return(GamespaceAliasAdapter(alias))

    @coroutine
    def get_gamespace_access_scopes(self, gamespace_id, db=None):

        try:
            gamespace_scopes = yield (db or self.db).get(
                """
                    SELECT `gamespace_scopes`
                    FROM `gamespace`
                    WHERE `gamespace_id`=%s;
                """, gamespace_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to get a gamespace access: " + e.args[1])

        if gamespace_scopes is None:
            raise GamespaceNotFound()

        raise Return(gamespace_scopes["gamespace_scopes"])

    @coroutine
    def list_all_aliases(self, db=None):
        try:
            gamespaces = yield (db or self.db).query(
                """
                    SELECT *
                    FROM `gamespace_aliases`;
                """)
        except DatabaseError as e:
            raise GamespaceError("Failed to list aliases: " + e.args[1])

        raise Return([GamespaceAliasAdapter(alias) for alias in gamespaces])

    @coroutine
    def list_gamespace_aliases(self, gamespace_id, db=None):
        try:
            gamespaces = yield (db or self.db).query(
                """
                    SELECT *
                    FROM `gamespace_aliases`
                    WHERE `gamespace_id`=%s;
                """, gamespace_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to get a names list: " + e.args[1])

        raise Return([GamespaceAliasAdapter(alias) for alias in gamespaces])

    @coroutine
    def list_gamespaces(self, db=None):
        try:
            gamespaces = yield (db or self.db).query(
                """
                    SELECT *
                    FROM `gamespace`;
                """)
        except DatabaseError as e:
            raise GamespaceError("Failed to list gamespaces: " + e.args[1])

        raise Return([GamespaceAdapter(gamespace) for gamespace in gamespaces])

    @coroutine
    def create_gamespace(self, gamespace_title, gamespace_scopes, db=None):

        scopes = common.access.serialize_scopes(gamespace_scopes)

        try:
            gamespace_id = yield (db or self.db).insert(
                """
                    INSERT INTO `gamespace`
                    (`gamespace_title`, `gamespace_scopes`)
                    VALUES (%s, %s);
                """, gamespace_title, scopes)
        except DatabaseError as e:
            raise GamespaceError("Failed to create a gamespace: " + e.args[1])

        raise Return(gamespace_id)

    @coroutine
    def create_gamespace_alias(self, name, gamespace_id, db=None):

        try:
            yield self.find_gamespace_alias(name)
        except NoSuchGamespaceAlias:
            pass
        else:
            raise GamespaceError("Such name already exists.")

        try:
            record_id = yield (db or self.db).insert(
                """
                    INSERT INTO `gamespace_aliases`
                    (`gamespace_name`, `gamespace_id`)
                    VALUES (%s, %s);
                """, name, gamespace_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to create an alias: " + e.args[1])

        raise Return(record_id)

    @coroutine
    def set_gamespace_access_scopes(self, gamespace_id, scopes, db=None):

        scopes = common.access.serialize_scopes(scopes)
        try:
            gamespace_id = int(gamespace_id)
        except ValueError:
            raise GamespaceError("gamespace_id expected to be a number.")

        try:
            yield self.get_gamespace_access_scopes(gamespace_id)
        except GamespaceNotFound:
            try:
                yield (db or self.db).insert(
                    """
                        INSERT INTO `gamespace`
                        (gamespace_id, `gamespace_scopes`)
                        VALUES (%s, %s);
                    """, gamespace_id, scopes)
            except DatabaseError as e:
                raise GamespaceError("Failed to create a gamespace: " + e.args[1])
        else:
            try:
                yield (db or self.db).insert(
                    """
                        UPDATE `gamespace`
                        SET `gamespace_scopes`=%s
                        WHERE `gamespace_id`=%s;
                    """, scopes, gamespace_id)
            except DatabaseError as e:
                raise GamespaceError("Failed to create a gamespace: " + e.args[1])

    @coroutine
    def update_gamespace(self, gamespace_id, gamespace_title, gamespace_scopes, db=None):

        scopes = common.access.serialize_scopes(gamespace_scopes)

        try:
            yield (db or self.db).execute(
                """
                    UPDATE `gamespace`
                    SET `gamespace_title`=%s, `gamespace_scopes`=%s
                    WHERE `gamespace_id`=%s;
                """, gamespace_title, scopes, gamespace_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to update a gamespace: " + e.args[1])

    @coroutine
    def update_gamespace_name(self, record_id, name, gamespace_id, db=None):
        try:
            yield (db or self.db).execute(
                """
                    UPDATE `gamespace_aliases`
                    SET `gamespace_name`=%s, `gamespace_id`=%s
                    WHERE `record_id`=%s;
                """, name, gamespace_id, record_id)
        except DatabaseError as e:
            raise GamespaceError("Failed to update a gamespace name: " + e.args[1])


class NoSuchGamespaceAlias(Exception):
    pass
