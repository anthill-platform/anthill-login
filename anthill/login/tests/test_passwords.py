
from tornado.testing import gen_test

from .. server import AuthServer
from .. model.password import UserExists, BadNameFormat, BadPassword
from .. import options as _opts

from anthill.common.testing import ServerTestCase
from anthill.common import random_string


class PasswordsTestCase(ServerTestCase):

    @classmethod
    def need_test_db(cls):
        return True

    @classmethod
    def get_server_instance(cls, db=None):
        return AuthServer(db)

    @gen_test
    async def test_format(self):
        # check without credential type
        with self.assertRaises(BadNameFormat):
            await self.application.passwords.create("singleword", "-")

        # check empty
        with self.assertRaises(BadNameFormat):
            await self.application.passwords.create("", "-")

        # check with empty credential type
        with self.assertRaises(BadNameFormat):
            await self.application.passwords.create(":test", "-")

        # check with empty username
        with self.assertRaises(BadNameFormat):
            await self.application.passwords.create("dev:", "-")

        # check way too long
        with self.assertRaises(BadNameFormat):
            await self.application.passwords.create("dev:" + random_string(512), "-")

    @gen_test
    async def test_exists(self):
        pwd = random_string(32)

        await self.application.passwords.create("dev:exists", pwd)

        with self.assertRaises(UserExists):
            await self.application.passwords.create("dev:exists", pwd)

    @gen_test
    async def test_update(self):
        pwd = random_string(32)

        async with self.test_db.acquire() as db:
            await self.application.passwords.create("dev:update", pwd, db=db)

            await self.application.passwords.login("dev:update", pwd, db=db)

            await self.application.passwords.update("dev:update", "other-" + pwd, db=db)

            with self.assertRaises(BadPassword):
                await self.application.passwords.login("dev:update", pwd, db=db)

    @gen_test
    async def test_password(self):
        async with self.test_db.acquire() as db:
            for t in range(1, 10):

                pwd = random_string(32)

                await self.application.passwords.create("dev:pwd", pwd, db=db)
                await self.application.passwords.login("dev:pwd", pwd, db=db)

                with self.assertRaises(BadPassword):
                    await self.application.passwords.login("dev:exists", "other-" + pwd, db=db)

                await self.application.passwords.delete("dev:pwd", db=db)
