
from anthill.common import cached
from anthill.common.options import options
from anthill.common.database import DatabaseError
from anthill.common.model import Model

import re
import logging
import ujson
import base64

from Crypto.Cipher import AES


BLOCK_SIZE = 32
PADDING = '{'


class KeyAdapter(object):
    def __init__(self, data):
        self.key_id = data.get("key_id")
        self.name = data.get("key_name")


class KeyDataError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class KeyNotFound(Exception):
    pass


def add_pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING


def encode(secret, decoded_value):

    if not secret:
        return decoded_value

    cipher = AES.new(secret.encode("utf8"), AES.MODE_ECB)
    pad = add_pad(decoded_value)
    encrypted = cipher.encrypt(pad.encode())
    return base64.b64encode(encrypted)


def decode(secret, encoded_value):
    if not secret:
        return encoded_value

    cipher = AES.new(secret.encode(), AES.MODE_ECB)
    b64decoded = base64.b64decode(encoded_value)
    decrypted = cipher.decrypt(b64decoded).decode("utf-8")
    return decrypted.rstrip(PADDING)


class KeyModel(Model):
    KEY_NAME_PATTERN = re.compile("^(\w+)$")

    def __init__(self, db):
        self.db = db

        self.secret = options.application_keys_secret

    def get_setup_tables(self):
        return ["gamespace_keys"]

    def get_setup_db(self):
        return self.db

    async def add_key(self, gamespace_id, key_name, key_data):

        KeyModel.validate_key(key_name)

        key_data = ujson.dumps(key_data)

        if self.secret:
            key_data = encode(self.secret, key_data)

        try:
            await self.find_key(gamespace_id, key_name)
        except KeyNotFound:
            try:
                key_id = await self.db.insert("""
                    INSERT INTO `gamespace_keys`
                    (`key_data`, `gamespace_id`, `key_name`)
                    VALUES (%s, %s, %s);
                """, key_data, gamespace_id, key_name)
            except DatabaseError as e:
                raise KeyDataError("Failed to add a key: " + e.args[1])

            return key_id
        else:
            raise KeyDataError("Key '{0}' already exists.".format(key_name))

    async def delete_key(self, gamespace_id, key_id):

        # just make sure it exists
        await self.get_key(gamespace_id, key_id)

        try:
            await self.db.execute("""
                DELETE FROM `gamespace_keys`
                WHERE `gamespace_id`=%s AND `key_id`=%s;
            """, gamespace_id, key_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to delete a key: " + e.args[1])

    async def find_key(self, gamespace_id, key_name):

        try:
            key = await self.db.get("""
                SELECT `key_id`, `key_name`
                FROM `gamespace_keys`
                WHERE `key_name`=%s AND `gamespace_id`=%s;
            """, key_name, gamespace_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to find a key: " + e.args[1])

        if key is None:
            raise KeyNotFound()

        return KeyAdapter(key)

    async def find_key_decoded(self, gamespace_id, key_name):

        KeyModel.validate_key(key_name)

        try:
            key = await self.db.get("""
                SELECT `key_data`
                FROM `gamespace_keys`
                WHERE `key_name`=%s AND `gamespace_id`=%s;
            """, key_name, gamespace_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to get a key: " + e.args[1])

        if key is None:
            raise KeyNotFound()

        key_data = key["key_data"]

        if self.secret:
            key_data = decode(self.secret, key_data)

        try:
            key_data = ujson.loads(key_data)
        except (KeyError, ValueError):
            raise KeyDataError("Corrupted key")

        return key_data

    async def find_keys_decoded(self, gamespace_id, keys):

        if not isinstance(keys, list):
            raise KeyDataError("Not a list")

        for key_name in keys:
            KeyModel.validate_key(key_name)

        try:
            keys = await self.db.query("""
                SELECT `key_data`, `key_name`
                FROM `gamespace_keys`
                WHERE `gamespace_id`=%s AND `key_name` IN ({0});
            """.format(",".join(["%s"] * len(keys))), gamespace_id, *keys)
        except DatabaseError as e:
            raise KeyDataError("Failed to get keys: " + e.args[1])

        result = {}

        for key in keys:
            key_data = key["key_data"]
            key_name = key["key_name"]

            if self.secret:
                key_data = decode(self.secret, key_data)

            result[key_name] = ujson.loads(key_data)

        return result

    async def get_key(self, gamespace_id, key_id):

        try:
            key = await self.db.get("""
                SELECT `key_id`, `key_name`
                FROM `gamespace_keys`
                WHERE `key_id`=%s AND `gamespace_id`=%s;
            """, key_id, gamespace_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to get a key: " + e.args[1])

        if key is None:
            raise KeyNotFound()

        return KeyAdapter(key)

    async def get_key_cached(self, gamespace, key_name, kv):
        # noinspection PyUnusedLocal
        @cached(kv=kv,
                h=lambda: "gamespace_key:" + str(gamespace) + ":" + key_name,
                ttl=300,
                json=True)
        async def get(*args, **kwargs):
            logging.info("Looking for key '{0}' in gamespace @{1}".format(key_name, gamespace))
            key_data = await self.find_key_decoded(gamespace, key_name)
            return key_data

        key = await get()

        return key

    async def get_key_decoded(self, gamespace_id, key_id):

        try:
            key = await self.db.get("""
                SELECT `key_data`
                FROM `gamespace_keys`
                WHERE `key_id`=%s AND `gamespace_id`=%s;
            """, key_id, gamespace_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to get a key: " + e.args[1])

        if key is None:
            raise KeyNotFound()

        key_data = key["key_data"]

        if self.secret:
            key_data = decode(self.secret, key_data)

        return ujson.loads(key_data)

    async def list_keys(self, gamespace_id):
        try:
            keys = await self.db.query("""
                SELECT `key_name`, `key_id`
                FROM `gamespace_keys`
                WHERE `gamespace_id`=%s;
            """, gamespace_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to list keys: " + e.args[1])

        return [KeyAdapter(key) for key in keys]

    async def check_keys(self, gamespace_id, keys_to_check):
        """
        Returns a list of keys that have been actually set for a gamespace
        """

        if not keys_to_check:
            return set()

        try:
            keys = await self.db.query("""
                SELECT `key_name`
                FROM `gamespace_keys`
                WHERE `gamespace_id`=%s AND `key_name` IN %s;
            """, gamespace_id, keys_to_check)
        except DatabaseError as e:
            raise KeyDataError("Failed to list keys: " + e.args[1])

        return set(key["key_name"] for key in keys)

    async def update_key(self, gamespace_id, key_id, key_name):

        KeyModel.validate_key(key_name)

        # just make sure it exists
        await self.get_key(gamespace_id, key_id)

        try:
            await self.db.execute("""
                UPDATE `gamespace_keys`
                SET `key_name`=%s
                WHERE `gamespace_id`=%s AND `key_id`=%s;
            """, key_name, gamespace_id, key_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to update a key: " + e.args[1])

    async def update_key_data(self, gamespace_id, key_id, key_data):

        key_data = ujson.dumps(key_data)

        if self.secret:
            key_data = encode(self.secret, key_data)

        # just make sure it exists
        await self.get_key(gamespace_id, key_id)

        try:
            await self.db.execute("""
                UPDATE `gamespace_keys`
                SET `key_data`=%s
                WHERE `gamespace_id`=%s AND `key_id`=%s;
            """, key_data, gamespace_id, key_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to update a key: " + e.args[1])

    @staticmethod
    def validate_key(key_name):
        if not KeyModel.KEY_NAME_PATTERN.match(key_name):
            raise KeyDataError("Bad key name")

    async def delete_gamespace(self, gamespace_id, db=None):
        """
        NEVER CALL THAT
        """

        try:
            await (db or self.db).execute("""
                DELETE FROM `gamespace_keys`
                WHERE `gamespace_id`=%s;
            """, gamespace_id)
        except DatabaseError as e:
            raise KeyDataError("Failed to delete all keys: " + e.args[1])
