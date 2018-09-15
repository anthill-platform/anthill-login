
from tornado.testing import gen_test

from .. server import AuthServer
from .. import options as _opts

from anthill.common.testing import ServerTestCase


class AccountsTestCase(ServerTestCase):
    @classmethod
    def need_test_db(cls):
        return True

    @classmethod
    def get_server_instance(cls, db=None):
        return AuthServer(db)

    @gen_test
    async def test_accounts(self):

        async with self.test_db.acquire() as db:
            account_id = int(await self.application.accounts.create_account(db=db))
            self.assertGreater(account_id, 0)

            info = await self.application.accounts.get_account_info(account_id, db=db)
            self.assertEqual(info, {})

            async def test_info(value, check):
                await self.application.accounts.update_account_info(account_id, value, db=db)
                account_info = await self.application.accounts.get_account_info(account_id, db=db)
                self.assertEqual(account_info, check)

            await test_info({"test": True}, {"test": True})
            await test_info({"test": False}, {"test": False})
            await test_info({"a": "string"}, {"test": False, "a": "string"})
            await test_info({"b": 5}, {"test": False, "a": "string", "b": 5})
            await test_info({"test": None}, {"a": "string", "b": 5})
            await test_info({"test": ["a", "b"]}, {"test": ["a", "b"], "a": "string", "b": 5})
