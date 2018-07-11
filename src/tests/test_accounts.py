
from tornado.gen import coroutine, Return, sleep
from tornado.testing import gen_test

# noinspection PyUnresolvedReferences
from server import AuthServer

import common.testing
from common import random_string
import options as _opts


class AccountsTestCase(common.testing.ServerTestCase):
    @classmethod
    def need_test_db(cls):
        return True

    @classmethod
    def get_server_instance(cls, db=None):
        return AuthServer(db)

    @gen_test
    def test_accounts(self):

        with (yield self.test_db.acquire()) as db:
            account_id = yield self.application.accounts.create_account(db=db)
            self.assertGreater(account_id, 0)

            info = yield self.application.accounts.get_account_info(account_id, db=db)
            self.assertEqual(info, {})

            @coroutine
            def test_info(value, check):
                yield self.application.accounts.update_account_info(account_id, value, db=db)
                info = yield self.application.accounts.get_account_info(account_id, db=db)
                self.assertEqual(info, check)

            yield test_info({"test": True}, {"test": True})
            yield test_info({"test": False}, {"test": False})
            yield test_info({"a": "string"}, {"test": False, "a": "string"})
            yield test_info({"b": 5}, {"test": False, "a": "string", "b": 5})
            yield test_info({"test": None}, {"a": "string", "b": 5})
            yield test_info({"test": ["a", "b"]}, {"test": ["a", "b"], "a": "string", "b": 5})
