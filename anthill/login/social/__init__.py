
from .. model import authenticator
from .. model.key import KeyNotFound


class SocialAuthenticator(authenticator.Authenticator):
    """
    Abstract authenticator to social networks (google, facebook etc)

    """

    def __init__(self, application, credential_type):
        super(SocialAuthenticator, self).__init__(application, credential_type)

    async def get_private_key(self, gamespace, data=None):

        if not data:
            try:
                data = await self.get_key(gamespace, self.type())
            except KeyNotFound:
                raise authenticator.AuthenticationError("key_not_found")

        # noinspection PyUnresolvedReferences
        return self.new_private_key(data)

    async def get_app_id(self, gamespace, data=None):
        private_key = await self.get_private_key(gamespace, data=data)
        return private_key.get_app_id()

    def has_auth_form(self):
        return False