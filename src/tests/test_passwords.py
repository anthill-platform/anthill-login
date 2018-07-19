
from tornado.gen import coroutine, Return, sleep
from tornado.testing import gen_test

# noinspection PyUnresolvedReferences
from server import AuthServer
from model.password import UserExists, BadNameFormat, BadPassword

from common.testing import ServerTestCase
from common import random_string
import options as _opts


class PasswordsTestCase(ServerTestCase):

    @classmethod
    def need_test_db(cls):
        return True

    @classmethod
    def get_server_instance(cls, db=None):
        return AuthServer(db)

    @gen_test
    def test_format(self):

        # check without credential type
        with self.assertRaises(BadNameFormat):
            yield self.application.passwords.create("singleword", "-")

        # check empty
        with self.assertRaises(BadNameFormat):
            yield self.application.passwords.create("", "-")

        # check with empty credential type
        with self.assertRaises(BadNameFormat):
            yield self.application.passwords.create(":test", "-")

        # check with empty username
        with self.assertRaises(BadNameFormat):
            yield self.application.passwords.create("dev:", "-")

        # check way too long
        with self.assertRaises(BadNameFormat):
            yield self.application.passwords.create("dev:" + random_string(512), "-")

    @gen_test
    def test_exists(self):
        pwd = random_string(32)

        yield self.application.passwords.create("dev:exists", pwd)

        with self.assertRaises(UserExists):
            yield self.application.passwords.create("dev:exists", pwd)

    @gen_test
    def test_update(self):
        pwd = random_string(32)

        with (yield self.test_db.acquire()) as db:
            yield self.application.passwords.create("dev:update", pwd, db=db)

            yield self.application.passwords.login("dev:update", pwd, db=db)

            yield self.application.passwords.update("dev:update", "other-" + pwd, db=db)

            with self.assertRaises(BadPassword):
                yield self.application.passwords.login("dev:update", pwd, db=db)

    @gen_test
    def test_password(self):

        with (yield self.test_db.acquire()) as db:
            for t in xrange(1, 10):

                pwd = random_string(32)

                yield self.application.passwords.create("dev:pwd", pwd, db=db)
                yield self.application.passwords.login("dev:pwd", pwd, db=db)

                with self.assertRaises(BadPassword):
                    yield self.application.passwords.login("dev:exists", "other-" + pwd, db=db)

                yield self.application.passwords.delete("dev:pwd", db=db)
