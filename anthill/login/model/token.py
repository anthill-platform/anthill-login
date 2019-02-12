
from anthill.common import keyvalue, access, sign

from anthill.common.gen import AccessTokenGenerator
from anthill.common.options import options
from anthill.common.model import Model
from anthill.common.access import AccessToken, AccessTokenCache, INVALIDATION_CHANNEL

import logging


class AccessTokenModel(Model, AccessTokenCache):

    DEFAULT_NAME = "def"

    def __init__(self, application):
        AccessTokenCache.__init__(self)

        self.application = application
        self.publisher = None
        self.kv = keyvalue.KeyValueStorage(
            host=options.tokens_host,
            port=options.tokens_port,
            db=options.tokens_db,
            max_connections=options.tokens_max_connections)

    async def started(self, application):
        self.publisher = await self.application.acquire_publisher()
        await super(AccessTokenModel, self).started(application)

    def has_delete_account_event(self):
        return True

    async def accounts_deleted(self, gamespace, accounts, gamespace_only):
        for account in accounts:
            await self.invalidate_account(account)

    async def subscribe(self):
        pass

    async def __invalidate_uuid__(self, db, account, uuid, affect_names=True):

        key = "id:" + uuid

        # pop the uuid
        pipe = db.pipeline()
        pipe.get(key, encoding="utf-8")
        pipe.delete(key)

        db_account, uuid_deleted = await pipe.execute()

        key = "account:" + str(account)

        pipe = db.pipeline()
        pipe.hget(key, uuid, encoding="utf-8")
        pipe.hdel(key, uuid)

        name, account_deleted = await pipe.execute()

        if affect_names and account_deleted and name:
            key = "names:" + str(account)
            await db.hdel(key, name)

        data = {
            "uuid": uuid,
            "account": account
        }

        logging.info("Invalidating a token for id '{0}' ".format(
            uuid))

        await self.publisher.publish(INVALIDATION_CHANNEL, data)

        return uuid_deleted or account_deleted

    async def extend(self, token, extend_with, scopes):
        """
        Extend access token rights with right of the another access token.
        """

        my_gamespace = token.get(
            access.AccessToken.GAMESPACE)

        extend_gamespace = extend_with.get(
            access.AccessToken.GAMESPACE)

        if str(extend_gamespace) != str(my_gamespace):
            raise TokensError("Tokens don't share gamespace")

        if scopes == "*":
            token.scopes.update(extend_with.scopes)
        else:
            required_scopes = access.parse_scopes(scopes)
            mix = list(set(extend_with.scopes) & set(required_scopes))
            token.scopes.update(mix)

        new_data = AccessTokenGenerator.refresh(
            sign.TOKEN_SIGNATURE_RSA,
            token,
            force=True)

        await self.save_token(token.account, token.uuid, new_data["expires"], invalidate=False)
        return new_data

    async def get_uuids(self, account):
        async with self.kv.acquire() as db:
            account_key = "account:" + str(account)
            uuids = await db.hgetall(account_key, encoding="utf-8")
            result = {}
            for uuid, name in uuids.items():
                key = "id:" + uuid
                ttl = await db.ttl(key)
                if ttl:
                    result[uuid] = {
                        "name": name,
                        "ttl": int(ttl)
                    }
                else:
                    await db.hdel(account_key, uuid)

        return result

    async def invalidate_account(self, account):

        async with self.kv.acquire() as db:
            account_key = "account:" + str(account)
            uuids = await db.hkeys(account_key, encoding="utf-8")
            for uuid in uuids:
                await self.__invalidate_uuid__(db, account, uuid)
        return True

    async def invalidate_uuid(self, account, uuid):
        async with self.kv.acquire() as db:
            return await self.__invalidate_uuid__(db, account, uuid)

    async def save_token(self, account, uuid, expire, name=None, invalidate=True):

        async with self.kv.acquire() as db:
            account_key = "account:" + str(account)
            names_key = "names:" + str(account)

            pipe = db.pipeline()

            key = "id:" + uuid
            pipe.setex(key, expire, account)
            pipe.hsetnx(account_key, uuid, name or AccessTokenModel.DEFAULT_NAME)
            await pipe.execute()

            if invalidate:
                name = name or AccessTokenModel.DEFAULT_NAME

                pipe = db.pipeline()
                pipe.hget(names_key, name, encoding="utf-8")
                pipe.hset(names_key, name, uuid)
                previous_uuid, new_uuid = await pipe.execute()

                # if there was a previous one, invalidate it
                if previous_uuid:
                    await self.__invalidate_uuid__(db, account, previous_uuid, affect_names=False)

            logging.info("Stored a token for user '{0}': '{1}' ".format(account, uuid))

    async def refresh(self, token):
        if not (await self.validate(token)):
            raise TokensError("Token is not valid")

        new_data = AccessTokenGenerator.refresh(
            sign.TOKEN_SIGNATURE_RSA, token)

        await self.save_token(
            token.account,
            token.uuid,
            new_data["expires"],
            invalidate=False)

        return new_data

    async def validate_db(self, token, db):

        issuer = token.get(AccessToken.ISSUER)

        # no issuer means no external validation
        if issuer is None:
            return True

        key = "id:" + token.uuid

        account_db = await db.get(key, encoding="utf-8")

        if not account_db:
            # if the uuid is not valid, remove it from the list

            pipe = db.pipeline()
            account_key = "account:" + str(token.account)
            pipe.hget(account_key, token.uuid, encoding="utf-8")
            pipe.hdel(account_key, token.uuid)

            name, deleted = await pipe.execute()

            if deleted and name:
                names_key = "names:" + str(token.account)
                await db.hdel(names_key, name)

            return False

        # keyvalue storage returns bytes, we have strings
        return token.account == account_db.encode()


class TokensError(Exception):
    def __init__(self, message):
        self.message = message
