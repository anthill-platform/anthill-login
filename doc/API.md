# Credential types

Login service allows to authenticate a player in a different ways.

### `anonymous`
A special way to authenticate without asking a player for usernames and passwords.
In order to auntenticate, client application randomly generates unique username 
and password, and stores it secure storage locally.

Is there's no such username, a new one will be created.

These arguments are expected during <a href="#authenticate">authentication</a>:

| Argument         | Description                                           |
|------------------|-------------------------------------------------------|
| `username`       | A random username (for example, a UUID)               |
| `key`            | A random password with considerable length            |

### `dev`
Same as above, but cannot be created client side. 
Used for administrative credentials, tools etc.

These arguments are expected during <a href="#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `username`       | A username                                    |
| `key`            | A password, the stronger is better            |

### `token`
A special way to authenticate, using existing token 
(for example, you would like to request more scopes, but don't want to process a full authentication again)

These arguments are expected during <a href="#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `access_token`   | Existing valid access token with the same gamespace as the requested |


### `google`
A way to authenticate using a Google account. 

To enable this feature, please do the following:

1. Create the Web Application <a href="https://console.developers.google.com/apis/credentials/oauthclient">OAuth Client ID</a> 
at the Google API Console;
2. Put the Login's service location (for example, `http(s)://login-dev.example.com`) 
into the `Authorized JavaScript origins` section;
3. Download a client secret JSON file;
4. Open the Anthill Admin tool and select the Login service;
5. Select the section "Keys" and click "Add New Key";
6. Type in "google" as a Key Name, and paste client secret, downloaded before, as a Key Data.

After these steps, login using google accounts will be available.

To do the actual authentication, authentication code should be obtained from the Google first.
Please see <a href="https://developers.google.com/identity/protocols/OAuth2WebServer">this page</a> 
for documentation about obtaining authentication code from Google.

These arguments are expected during <a href="#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `key`            | Authentication code from Google |

### `facebook`
A way to authenticate using a facebook account. 

To enable this feature, please do the following:

1. Create a <a href="https://developers.facebook.com/apps/">New Application</a> 
at the Facebook Developers section;
2. Put the Login's service location (for example, `http(s)://login-dev.example.com`) 
into the `Valid OAuth redirect URIs` section (under Facebook Login product);
3. Create such JSON object:

```json
{
    "app-id": "<app-id>",
    "app-secret": "<app-secret>"
}
```

And replace `<app-id>` and `<app-secret>` with the App ID and App Secret respectively 
at the Application Dashboard;

4. Open the Anthill Admin tool and select the Login service;
5. Select the section "Keys" and click "Add New Key";
6. Type in "facebook" as a Key Name, and paste JSON object, created before, as a Key Data.

After these steps, login using google accounts will be available.

To do the actual authentication, <a href="https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension">Short-Lived Access Token</a> 
should be obtained from the Facebook first.

These arguments are expected during <a href="#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `key`            | Short-Lived Access Token from Facebook |

### `gamecenter`
A way to authenticate using a Apple's Game Center. Please note, this way is only possible on `iOS`.

This way may look complicated, however it can be described in a few steps:

1. Generate <a href="https://developer.apple.com/reference/gamekit/gklocalplayer/1515407-generateidentityverificationsign?language=objc">a signature</a> for the player;
2. At the return, you will have such: `publicKeyUrl`, `signature`, `salt`  and `timestamp`;
3. Pass them respectively as the expected arguments.

These arguments are expected during <a href="#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `public_key`     | A `publicKeyUrl` returned from generation process |
| `signature`      | A generated `signature` |
| `salt`           | A generated `salt` |
| `timestamp`      | A generated `timestamp` |
| `bundle_id`      | Bundle ID of your Application |
| `username`       | A <a href="https://developer.apple.com/reference/gamekit/gkplayer/1521127-playerid?language=objc">playerID</a> retreived from iOS |


### `steam`
A way to authenticate using a Steam Account.

These arguments are expected during <a href="#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `ticket`         | Session ticket <a href="https://partner.steamgames.com/documentation/auth#client_to_backend_webapi">acquired from Steam API</a>        |
| `app_id`         | Application ID (`app_id.txt`) to authenticate for        |

# REST API Requests

## Authenticate

Authenticates the user in the Anthill Platform

#### ← Request

```rest
POST /auth
```

| Argument         | Description                                                                                    |
|------------------|------------------------------------------------------------------------------------------------|
| `credential`     | <a href="#credential-types">Credential type</a>                                                |
| `scopes`         | Comma-separates list of access scopes to request                                               |
| `gamespace`      | A gamespace name (alias) to authenticate in                                                    |

Optional arguments:

| Argument         | Description                                                                         | Default value |
|------------------|-------------------------------------------------------------------------------------|---------------|
| `should_have`    | Comma-separated list of scopes the user should definately acquire, or `403 Forbidden` will be returned. Useful in cases when player is OK with not having some of scopes.  |  `*`, everything requested should be retrurned.          |
| `info`           | A JSON object of the additional info would be attached to account (for example, device ID)  |  `{}`             |
| `attach_to`      | Access token of the account to proceed the attach procedure.                        |               |
| `unique`         | Should the access token be unique (meaning no two tokens of the same name could exists). Setting to `false` would require a special access scope `auth_non_unique`. | `true` |
| `as`             | A name for the token. Only one token of the same name could exist at the same time (if `unique` is `true`) | `def`         |
| `full`           | Return more information about the roken returned (if form of a JSON object instead of just token``) | `false`         |

#### → Response

In case of success, an access token is returned:
```
"token string"
```

**Warning**: token string format could be changed at any moment, so the client application
should not rely on this response, and should threat it like a simple string.

If the argument `full` is set to `true`, a JSON object is returned instead:

```
{
    "token": "<token string>",
    "account": "<account ID>",
    "credential": "<credential>",
    "scopes": [<array of allowed scopes>]
}
```

| Response         | Description                                          |
|------------------|------------------------------------------------------|
| `200 OK`         | Everything went OK, service location follows.        |
| `404 Bad Arguments` | Some arguments are missing or wrong.        |
| `403 Forbidden`  | Failed to acquire a token, either username/password is wrong, or access is denied.                                |
| `409 Conflict`  | A merge conflict is happened, <a href="#resolve-conflict">conflict resolve</a> is required |

## Resolve Conflict

TODO