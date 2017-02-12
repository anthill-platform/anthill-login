# Player Accounts

Login service have simple account system: 
each player have unique personal account number attached to him. 
If the user is logged in for a first time, 
a new account is created automatically.

However, player may have multiple credentials that prove same account. 
For example, user could login using `google` or `facebook`, but both of 
them will lead to the same account.

<div align="center"><img src="https://cloud.githubusercontent.com/assets/1666014/22863400/e726fd64-f147-11e6-948f-e6338992a390.png" width="561"></div>

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
6. Type in `google` as a Key Name, and paste client secret, downloaded before, as a Key Data.

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

And replace `<app-id>` and `<app-secret>` with the App ID and App Secret respectively;

4. Open the Anthill Admin tool and select the Login service;
5. Select the section "Keys" and click "Add New Key";
6. Type in `facebook` as a Key Name, and paste JSON object, created before, as a Key Data.

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

To enable this feature, a WebAPI key should be used:

1. Create a <a href="https://partner.steamgames.com/documentation/webapi#creating">WebAPI key</a>;
2. Create such JSON object:

```json
{
    "app_id": "<app_id>",
    "key": "<key>"
}
```

And replace `<app_id>` and `<key>` with the Application ID (`app_id.txt`) and WebAPI key respectively;

3. Open the Anthill Admin tool and select the Login service;
4. Select the section "Keys" and click "Add New Key";
5. Type in `steam` as a Key Name, and paste JSON object, created before, as a Key Data.

These arguments are expected during <a href="#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `ticket`         | Session ticket <a href="https://partner.steamgames.com/documentation/auth#client_to_backend_webapi">acquired from Steam API</a>        |
| `app_id`         | Application ID (`app_id.txt`) to authenticate for        |

# Keys

Login service allows to securely store private keys for external social services. 
For example,

* A Google's OAuth Secret
* Facebook App ID and Secret
* Steam app_id and WebAPI key

To manage these keys:

1. Open the Anthill Admin tool;
3. Select the Login service;
3. Select the section "Keys";

Other services can use these keys to communicate with external services.
For example, a `social` service may use `google` key to fetch player's friend list.

Please note that there can only be one key with same name, for a gamespace.
If you would like to have a few keys with same name, put a new one under different gamespace.

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
| `attach_to`      | Access token of the account to proceed the attach procedure. See <a href="#attach-credential">Attach Credential</a> for more information.                    |               |
| `unique`         | Should the access token be unique (meaning no two tokens of the same name could exists). Setting to `false` would require a special access scope `auth_non_unique`. | `true` |
| `as`             | A name for the token. Only one token of the same name could exist at the same time (if `unique` is `true`) | `def`         |
| `full`           | Return more information about the token returned (if form of a JSON object instead of just token) | `false`         |

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
| `409 Conflict`  | A merge conflict is happened, a <a href="#resolve-conflict">Conflict Resolve</a> is required |

## Attach Credential

If you login with a credential for the first time, a fresh new account is created.
However, sometimes it is not the case. For example, a player have already authenticated into credential `anonymous:XX-XX-XX`, so the account `A` is created.

```
    anonymous:XX-XX-XX -> A
```
But if player also wants to login using `facebook`, he will end up with a different account.
```
    anonymous:XX-XX-XX -> A
    facebook:12345678  -> B
```
To avoid this, credential can be attached to a same account instead of creating new one.
```
    anonymous:XX-XX-XX -> A
    facebook:12345678  -> A
```

Simplest way to do so is to pass `attach_to` argument while doing <a href="#authenticate">Authenticate</a> call:

1. Authenticate, using first credential (say `anonymous:XX-XX-XX`), account `A` will be used (or created);
2. Authenticate, using second credential (say `facebook:12345678`). While doing that, pass the access
token from a previous authentication, as `attach_to` argument;
3. The system will try to attach credential `facebook:12345678` to account `A` as long as credential
is not used elsewhere;

In case credential `facebook:12345678` has already attached to a different account, or already
has multiple accounts attached, a conflict will occur:
 
```
{
    "result_id": "<Conflict Reason>",
    // other useful information about the conlict
}
```
In response to conflict, server may return `resolve_token` to <a href="#resolve-conflict">Resolve Conflict</a>.
Possible conflict reasons:

#### `merge_required`

Credential, you are trying to attach is already attached to a different account. 
Possible account solutions along with their profiles (if exist) are described in field `accounts`.

```
{
    "result_id": "merge_required",
    "resolve_token": "<a resolve token>",
    "accounts": {
        "local": {
            "account": <account N>,
            "credential": <credentian N>,
            "profile": { a possible profile JSON object }
        },
        "remote": {
            "account": <account N>,
            "credential": <credentian N>,
            "profile": { a possible profile JSON object }
        }
    }
}
```

Profile fields may be used to describe to the Player information about the accounts (level reached, currency have, avatar etc).
On of the solutions should be used as `resolve_with` when dealing with <a href="#resolve-conflict">Resolve Conflict</a>.

#### `multiple_accounts_attached`

Credential, you are trying to attach is already attached to a multiple accounts. 
One of them is required to be detached first.
Please note that this may happen during normal authentication.

```
{
    "result_id": "multiple_accounts_attached",
    "resolve_token": "<a resolve token>",
    "accounts": [
        {
            "account": <account number>,
            "profile": { a possible profile JSON object }
        },
        {
            "account": <account number>,
            "profile": { a possible profile JSON object }
        },
        ... 
    ]
}
```
On of the account numbers should be used as `resolve_with` when dealing with <a href="#resolve-conflict">Resolve Conflict</a>.

## Resolve Conflict

I case of conflict, a Resolve Conflict method may be used to solve the conflict situation.

#### ← Request

```rest
POST /resolve
```

| Argument         | Description                                                                                    |
|------------------|------------------------------------------------------------------------------------------------|
| `access_token`   | A Resolve Token, retrieved when the conflict occurred.                                                |
| `resolve_method` | A way how to resolve this conflict. Should be exactly the Conflict Reason server gave. For example, `merge_required` or `multiple_accounts_attached`.                                               |
| `scopes`         | Access scopes to be acquired like in <a href="#authenticate">Authenticate</a> procedure. |
| `resolve_with`   | A way to resolve this conflict. Varies for different Conflict Reasons |

Optional arguments:

| Argument         | Description                                                                         |
|------------------|-------------------------------------------------------------------------------------|
| `attach_to`      | Access Token to the account player originally was going to attach to. Only applicable if conflict happened during <a href="#attach-credential">Attach Credential</a> procedure. |
| `full`           | Return more information about the token returned (if form of a JSON object instead of just token) |

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

## Validate Access Token

Checks if the given access token is valid

#### ← Request

```rest
GET /validate
```

| Argument         | Description                                |
|------------------|--------------------------------------------|
| `access_token`   | Access token to validate.                  |

#### → Response

This request has no response body.

| Response            | Description                                          |
|---------------------|------------------------------------------------------|
| `200 OK`            | Access token is valid.                               |
| `404 Bad Arguments` | Some arguments are missing or wrong.                 |
| `403 Forbidden`     | Token is not valid.                                  |


## Extend Access Token

Allows to to give additional Access Scopes to the existing access token 
(account of which did not have such scopes originally), 
using other, more powerful account.

1. Say there's account `A` with scopes `S1` and `S2` allowed.
2. There's account `B` with scope `S10` that `A` has no access to.
3. `A` authenticates, requesting scope `S1`.
4. `B` authenticates, requesting scope `S10`.
5. Access token of `B` extends access token `A` using scope he had `S10`.
6. A working access token for `A` with scopes `S1` and `S10` is now available.

This flow is primarily used for trusted game servers to do strict actions server side. 
For example,

1. User Authenticates asking for `profile` scope. This scope allows only to read user
profile, but not to write;
2. The Game Server Authenticates itself using `dev` credential with `profile_write` scope;
3. User give the access token to the server is a secure way;
4. The Game Server extends this token to the more powerful one, 
so server can write the profile in behalf of the user;
5. At the same time, user still have perfectly working access token, without such possibility;

#### ← Request

```rest
POST /extend
```

| Argument         | Description                                |
|------------------|--------------------------------------------|
| `access_token`   | Access token to extend (the one to be improved) |
| `extend`   | Access token to extend with (the one that have required scopes) |
| `scopes`   | Scopes to improve `access_token` with. Default `*` – to use all scopes the scope `extend` have. Otherwise, a comma-separate list of Access Scopes. |

#### → Response

A JSON object with a new token and it's expiration date.

```
{
    "token": "<improved access token>",
    "expires_in": <time, in seconds, for the new token to expire>
}
```

Please note that the original access token is still valid.
Also, tokens have to be in a same gamespace.

| Response            | Description                                          |
|---------------------|------------------------------------------------------|
| `200 OK`            | Access token has been improved                       |
| `404 Bad Arguments` | Some arguments are missing or wrong.                 |
| `403 Forbidden`     | One of tokens is not valid.                           |
