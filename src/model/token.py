
import logging

from tornado.gen import coroutine, Return, Task
from common.options import options

from common.access import AccessTokenCache, INVALIDATION_CHANNEL

import common.keyvalue
import common.access
import common.sign
import common.pubsub

from gen import AccessTokenGen


class AccessTokenModel(AccessTokenCache):

    DEFAULT_NAME = "def"

    def __init__(self, application):
        AccessTokenCache.__init__(self)

        self.application = application

        self.publisher = common.pubsub.RabbitMQPublisher(
            channels=[INVALIDATION_CHANNEL],
            broker=options.pubsub,
            name="login-publisher",
            channel_prefetch_count=options.internal_channel_prefetch_count)

        self.kv = common.keyvalue.KeyValueStorage(
            host=options.tokens_host,
            port=options.tokens_port,
            db=options.tokens_db,
            max_connections=options.tokens_max_connections)

    @coroutine
    def start(self):
        yield self.publisher.start()

    @coroutine
    def release(self):
        yield self.publisher.release()

    @coroutine
    def __invalidate_uuid__(self, db, account, uuid, affect_names=True):

        key = "id:" + uuid

        # pop the uuid
        with db.pipeline() as pipe:
            pipe.get(key)
            pipe.delete(key)

            db_account, uuid_deleted = yield Task(pipe.execute)

        key = "account:" + str(account)

        with db.pipeline() as pipe:

            pipe.hget(key, uuid)
            pipe.hdel(key, uuid)

            name, account_deleted = yield Task(pipe.execute)

        if affect_names and account_deleted and name:
            key = "names:" + str(account)
            yield Task(db.hdel, key, name)

        data = {
            "uuid": uuid,
            "account": account
        }

        logging.info("Invalidating a token for id '{0}' ".format(
            uuid))

        yield self.publisher.publish(INVALIDATION_CHANNEL, data)

        raise Return(uuid_deleted or account_deleted)

    @coroutine
    def extend(self, token, extend_with, scopes):
        """
        Extend access token rights with right of the another access token.
        """

        my_gamespace = token.get(
            common.access.AccessToken.GAMESPACE)

        extend_gamespace = extend_with.get(
            common.access.AccessToken.GAMESPACE)

        if str(extend_gamespace) != str(my_gamespace):
            raise TokensError("Tokens don't share gamespace")

        if scopes == "*":
            token.scopes.extend(extend_with.scopes)
        else:
            required_scopes = common.access.parse_scopes(scopes)
            mix = list(set(extend_with.scopes) & set(required_scopes))
            token.scopes.extend(mix)

        new_data = AccessTokenGen.refresh(
            common.sign.TOKEN_SIGNATURE_RSA,
            token,
            force=True)

        yield self.save_token(
            token.account,
            token.uuid,
            new_data["expires"],
            invalidate=False)

        raise Return(new_data)

    @coroutine
    def get_uuids(self, account):
        db = self.kv.acquire()

        try:
            account_key = "account:" + str(account)

            uuids = yield Task(db.hgetall, account_key)

            result = {}

            for uuid, name in uuids.iteritems():
                key = "id:" + uuid
                ttl = yield Task(db.ttl, key)

                if ttl:
                    result[uuid] = {
                        "name": name,
                        "ttl": int(ttl)
                    }
                else:
                    yield Task(
                        db.hdel,
                        account_key, uuid
                    )
        finally:
            yield db.release()

        raise Return(result)

    @coroutine
    def invalidate_account(self, account):

        db = self.kv.acquire()
        try:

            account_key = "account:" + str(account)

            uuids = yield Task(db.hkeys, account_key)

            for uuid in uuids:
                yield self.__invalidate_uuid__(db, account, uuid)

        finally:
            yield db.release()

        raise Return(True)

    @coroutine
    def invalidate_uuid(self, account, uuid):

        db = self.kv.acquire()

        try:
            result = yield self.__invalidate_uuid__(db, account, uuid)
        finally:
            db.release()

        raise Return(result)

    @coroutine
    def save_token(self, account, uuid, expire, name=None, invalidate=True):

        db = self.kv.acquire()
        try:
            account_key = "account:" + str(account)
            names_key = "names:" + str(account)

            with db.pipeline() as pipe:

                key = "id:" + uuid
                pipe.setex(key, expire, account)
                pipe.hsetnx(account_key, uuid, name or AccessTokenModel.DEFAULT_NAME)
                yield Task(pipe.execute)

                if invalidate:
                    name = name or AccessTokenModel.DEFAULT_NAME

                    pipe.hget(names_key, name, uuid)
                    pipe.hset(names_key, name, uuid)
                    previous_uuid, new_uuid = yield Task(pipe.execute)

                    # if there was a previous one, invalidate it
                    if previous_uuid:
                        yield self.__invalidate_uuid__(db, account, previous_uuid, affect_names=False)

                logging.info("Stored a token for user '{0}': '{1}' ".format(account, uuid))
        finally:
            yield db.release()

    @coroutine
    def refresh(self, token):
        if not (yield self.validate(token)):
            raise TokensError("Token is not valid")

        new_data = AccessTokenGen.refresh(
            common.sign.TOKEN_SIGNATURE_RSA, token)

        yield self.save_token(
            token.account,
            token.uuid,
            new_data["expires"],
            invalidate=False)

        raise Return(new_data)

    def subscribe(self):
        pass

    @coroutine
    def validate_db(self, token, db):
        key = "id:" + token.uuid

        account_db = yield Task(db.get, key)

        if not account_db:
            # if the uuid is not valid, remove it from the list

            with db.pipeline() as pipe:
                account_key = "account:" + str(token.account)
                pipe.hget(account_key, token.uuid)
                pipe.hdel(account_key, token.uuid)

                name, deleted = yield Task(pipe.execute)

            if deleted and name:
                names_key = "names:" + str(token.account)
                yield Task(db.hdel, names_key, name)

        raise Return(token.account == account_db)


class TokensError(Exception):
    def __init__(self, message):
        self.message = message
