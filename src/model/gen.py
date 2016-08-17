
import common.server
import common.access
import jwt

from uuid import uuid4
from common.access import AccessToken


MAX_TIME = 86400 * 60
ADMIN_TIME = 15 * 60


class AccessTokenGen(AccessToken):
    """
    Access token generator.

    Signs an access token using private key.
    Can be verified later using public key.
    """

    @staticmethod
    def generate(signer_id, requested_scopes, additional_containers, name=None,
                 uuid=None, max_time=None, token_only=False):

        for_time = max_time
        if for_time is None:
            for_time = MAX_TIME

        if any(scope_name.endswith("_admin") for scope_name in requested_scopes):
            for_time = min(ADMIN_TIME, for_time)

        if uuid is None:
            uuid = str(uuid4())

        if signer_id not in AccessToken.SIGNERS:
            raise common.server.ServerError("No such signer: '{0}'".format(signer_id))

        signer = AccessToken.SIGNERS[signer_id]
        now = int(common.access.utc_time())

        containers = {}

        if name is not None:
            containers[AccessToken.USERNAME] = name

        containers.update(additional_containers)

        containers.update({
            AccessToken.SCOPES: ",".join(requested_scopes),
            AccessToken.ISSUED_AT: str(now),
            AccessToken.EXPIRATION_DATE: str(now + for_time),
            AccessToken.UUID: uuid
        })

        access_token = jwt.encode(
            containers, signer.sign_key(),
            algorithm=signer_id,
            password=signer.sign_password())

        if token_only:
            return access_token

        return {
            "expires": for_time,
            "key": access_token,
            "uuid": uuid
        }

    @staticmethod
    def refresh(signer_id, token, force=False):
        if not token.is_valid():
            raise common.server.ServerError("Token is not valid")
        if not force and not token.needs_refresh():
            raise common.server.ServerError("Token refresh is not necessary")

        return AccessTokenGen.generate(
            signer_id,
            token.scopes,
            token.fields,
            name=token.name,
            uuid=token.uuid)
