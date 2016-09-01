
from tornado.gen import coroutine, Return, sleep
from tornado.testing import gen_test

from server import AuthServer
from model.password import UserExists, BadNameFormat, BadPassword

import common.testing
from common import random_string
import options as _opts


class PasswordsTestCase(common.testing.ServerTestCase):

    @classmethod
    @coroutine
    def co_setup_class(cls):
        cls.db = yield cls.get_test_db()

        cls.app = AuthServer(cls.db)
        cls.passwords = cls.app.passwords

        yield cls.app.started()

    @gen_test
    def test_format(self):

        # check without credential type
        with self.assertRaises(BadNameFormat):
            yield self.passwords.create("singleword", "-")

        # check empty
        with self.assertRaises(BadNameFormat):
            yield self.passwords.create("", "-")

        # check with empty credential type
        with self.assertRaises(BadNameFormat):
            yield self.passwords.create(":test", "-")

        # check with empty username
        with self.assertRaises(BadNameFormat):
            yield self.passwords.create("dev:", "-")

        # check way too long
        with self.assertRaises(BadNameFormat):
            yield self.passwords.create("dev:" + random_string(512), "-")

    @gen_test
    def test_exists(self):
        pwd = random_string(32)

        yield self.passwords.create("dev:exists", pwd)

        with self.assertRaises(UserExists):
            yield self.passwords.create("dev:exists", pwd)

    @gen_test
    def test_update(self):
        pwd = random_string(32)

        with (yield self.db.acquire()) as db:
            yield self.passwords.create("dev:update", pwd, db=db)

            yield self.passwords.login("dev:update", pwd, db=db)

            yield self.passwords.update("dev:update", "other-" + pwd, db=db)

            with self.assertRaises(BadPassword):
                yield self.passwords.login("dev:update", pwd, db=db)

    @gen_test
    def test_password(self):

        with (yield self.db.acquire()) as db:
            for t in xrange(1, 10):

                pwd = random_string(32)

                yield self.passwords.create("dev:pwd", pwd, db=db)
                yield self.passwords.login("dev:pwd", pwd, db=db)

                with self.assertRaises(BadPassword):
                    yield self.passwords.login("dev:exists", "other-" + pwd, db=db)

                yield self.passwords.delete("dev:pwd", db=db)
