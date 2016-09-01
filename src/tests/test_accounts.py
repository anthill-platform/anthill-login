
from tornado.gen import coroutine, Return, sleep
from tornado.testing import gen_test

from server import AuthServer

import common.testing
from common import random_string
import options as _opts


class PasswordsTestCase(common.testing.ServerTestCase):

    @classmethod
    @coroutine
    def co_setup_class(cls):
        cls.db = yield cls.get_test_db()

        cls.app = AuthServer(cls.db)
        cls.accounts = cls.app.accounts

        yield cls.app.started()

    @gen_test
    def test_accounts(self):

        with (yield self.db.acquire()) as db:
            account_id = yield self.accounts.create_account(db=db)
            self.assertGreater(account_id, 0)

            info = yield self.accounts.get_account_info(account_id, db=db)
            self.assertEqual(info, {})

            @coroutine
            def test_info(value, check):
                yield self.accounts.update_account_info(account_id, value, db=db)
                info = yield self.accounts.get_account_info(account_id, db=db)
                self.assertEqual(info, check)

            yield test_info({"test": True}, {"test": True})
            yield test_info({"test": False}, {"test": False})
            yield test_info({"a": "string"}, {"test": False, "a": "string"})
            yield test_info({"b": 5}, {"test": False, "a": "string", "b": 5})
            yield test_info({"test": None}, {"a": "string", "b": 5})
            yield test_info({"test": ["a", "b"]}, {"test": ["a", "b"], "a": "string", "b": 5})
