import hashlib
import re
import common.access
import hmac
import base64


from tornado.gen import coroutine, Return
from common.options import options
from common.database import DatabaseError
from common.model import Model


class PasswordAdapter(object):
    def __init__(self, data):
        self.credential = data.get("credential")
        self.password = data.get("password")
        self.algorithm = data.get("algorithm")


class PasswordsModel(Model):
    NAME_PATTERN = re.compile("^([a-zA-Z0-9_-]+)$")
    ALGORITHMS = {
        "HMACSHA256": lambda c, password, salt: base64.b64encode(
            hmac.new(key=str(c + salt), msg=str(password), digestmod=hashlib.sha256).digest()),
        "2SHA256": lambda c, password, salt: hashlib.sha256(
            hashlib.sha256(password + salt).hexdigest()).hexdigest(),
        "SHA256": lambda c, password, salt: hashlib.sha256(
            password).hexdigest()
    }
    DEFAULT_ALGORITHM = "HMACSHA256"

    def __generate_password__(self, credential, algorithm, password):
        return PasswordsModel.ALGORITHMS[algorithm](credential, password, self.salt)

    def __init__(self, application, db):
        self.db = db
        self.app = application
        self.salt = options.passwords_salt or ""

    def get_setup_tables(self):
        return ["credential_passwords"]

    def get_setup_db(self):
        return self.db

    @coroutine
    def setup_table_credential_passwords(self):
        yield self.create("dev:root", "anthill")

    @coroutine
    def update(self, username, password, db=None):
        """
        Updates a record in password database (should exist)
        """
        self.validate(username)

        try:
            result = yield (db or self.db).execute(
                """
                    UPDATE `credential_passwords`
                    SET `password`=%s, `algorithm`=%s
                    WHERE `credential`=%s
                """,
                self.__generate_password__(username, PasswordsModel.DEFAULT_ALGORITHM, password),
                PasswordsModel.DEFAULT_ALGORITHM, username)
        except DatabaseError as e:
            raise PasswordError("Failed to update a password: " + e.args[1])

        raise Return(result)

    @coroutine
    def create(self, username, password, db=None):
        """
        Creates a new password record for a credential, if not exists. Otherwise, UserExists raised.
        :returns associated account with this credential. If not exists, it gets allocated.
        :raises UserExists
        """

        if not re.match(PasswordsModel.NAME_PATTERN, self.validate(username)[1]):
            raise BadNameFormat()

        try:
            yield self.get(username)
        except UserNotFound:
            pass
        else:
            raise UserExists()

        try:
            yield (db or self.db).insert(
                """
                    INSERT INTO `credential_passwords`
                    (`credential`, `password`, `algorithm`)
                    VALUES (%s, %s, %s);
                """, username,
                self.__generate_password__(username, PasswordsModel.DEFAULT_ALGORITHM, password),
                PasswordsModel.DEFAULT_ALGORITHM)
        except DatabaseError as e:
            raise PasswordError("Failed to create a password: " + e.args[1])

        account_id = yield self.app.accounts.lookup_account(username)

        raise Return(account_id)

    @coroutine
    def delete(self, credential, db=None):
        """
        Deletes a password for a credential.
        """
        try:
            result = yield (db or self.db).execute(
                """
                    DELETE FROM `credential_passwords`
                    WHERE `credential`=%s;
                """, credential)
        except DatabaseError as e:
            raise PasswordError("Failed to delete a password: " + e.args[1])

        raise Return(result)

    @coroutine
    def get(self, credential, db=None):
        """
        Looks for a password for a credential.
        """
        self.validate(credential)

        try:
            result = yield (db or self.db).get(
                """
                    SELECT `password`, `algorithm`
                    FROM `credential_passwords`
                    WHERE `credential`=%s;
                """, credential)
        except DatabaseError as e:
            raise PasswordError("Failed to get a password: " + e.args[1])

        if not result:
            raise UserNotFound()

        raise Return(PasswordAdapter(result))

    @coroutine
    def login(self, credential, password, db=None):
        """
        Proceeds an authorization for an account. If password is valid, nothing happens.
        :raises UserNotFound
        :raises BadPassword
        """

        account = yield self.get(credential, db=db)

        if account is None:
            raise UserNotFound()

        account_password = account.password

        if self.__generate_password__(credential, account.algorithm, password) == account_password:
            raise Return(account)

        raise BadPassword()

    def validate(self, credential):
        """
        Check if credential has valid format (xxx:xxxxxxx)
        :returns a list of two elements [credential_type, username]
        :raises BadNameFormat
        """
        parsed = common.access.parse_account(credential)

        if not parsed:
            raise BadNameFormat()

        return parsed


class BadPassword(Exception):
    pass


class PasswordError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class BadNameFormat(Exception):
    pass


class UserNotFound(Exception):
    pass


class UserExists(Exception):
    pass
