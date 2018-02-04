
# Credential types

Login service allows to authenticate a player in a different ways:

* <a href="#anonymous">anonymous</a> – authenticate anonymously;
* <a href="#dev">dev</a> – developer accounts;
* <a href="#google">google</a> – with Google account;
* <a href="#facebook">facebook</a> – with Facebook account;
* <a href="#vk">vk</a> – with VKontakte (vk.com) account;
* <a href="#gamecenter">gamecenter</a> – with Apple's Game Center;
* <a href="#steam">steam</a> – with Steam account;
* <a href="#mailru">mailru</a> – with Mail.Ru Games account;
* <a href="#token">token</a> – using existing token;

To authenticate with corresponding credential type, pass the appropriate credential type as `credential` field during
<a href="API.md#authenticate">authentication</a>.

# anonymous

A special way to authenticate without asking a player for usernames and passwords.
In order to authenticate, client application randomly generates unique username 
and password, and stores it in secure storage locally.

Is there's no such username, a new one will be created.

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                           |
|------------------|-------------------------------------------------------|
| `username`       | A random username (for example, a UUID)               |
| `key`            | A random password with considerable length            |

# dev

Same as above, but cannot be created client side. 
Used for administrative credentials, tools etc.

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `username`       | A username                                    |
| `key`            | A password, the stronger is better            |

# google

A way to authenticate using a Google account. 

To enable this feature, please do the following:

1. Create the Web Application <a href="https://console.developers.google.com/apis/credentials/oauthclient">OAuth Client ID</a> 
at the Google API Console;
2. Add the application website (for example, `http(s)://example.com/`) into the `Authorized redirect URIs` list.
3. Open the Anthill Admin tool and select the Login service;
4. Select the section "Keys" and click "Add New Key";
5. Select `google` as Key Type, click Proceed
6. Fill Client ID and Client Secret fields according to your credentials:

<img src="https://user-images.githubusercontent.com/1666014/35532809-3715df0a-0544-11e8-928f-24b8987c0314.png" width="330">

After these steps, login using Google accounts will be available.

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `code`           | OAuth 2.0 authentication code.                |
| `redurect_uri`   | OAuth 2.0 redirect location.                  |

See <a href="#oauth-20">OAuth 2.0</a> section to how obtain these arguments.

# facebook

A way to authenticate using a Facebook account. 

To enable this feature, please do the following:

1. Create a <a href="https://developers.facebook.com/apps/">New Application</a> 
at the Facebook Developers section;
2. Add the application website (for example, `http(s)://example.com/`) 
into the `Valid OAuth redirect URIs` section (under Facebook Login product);
3. Open the Anthill Admin tool and select the Login service;
4. Select the section "Keys" and click "Add New Key";
5. Select in `facebook` as a Key Type.
6. Fill the App ID and App Secret respectively:

<img src="https://user-images.githubusercontent.com/1666014/35532940-9599a318-0544-11e8-95ed-bd6dcb655a67.png" width="330">

After these steps, login using Facebook accounts will be available.

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `code`           | OAuth 2.0 authentication code.                |
| `redurect_uri`   | OAuth 2.0 redirect location.                  |

See <a href="#oauth-20">OAuth 2.0</a> section to how obtain these arguments.

# vk

A way to authenticate using a VKontakte (vk.com) account. 

To enable this feature, please do the following:

1. Create a <a href="https://vk.com/editapp?act=create">New Application</a> 
at the Developers section;
2. Add the application website (for example, `http(s)://example.com/`) 
into the `Authorized redirect URI`;
3. Open the Anthill Admin tool and select the Login service;
4. Select the section "Keys" and click "Add New Key";
5. Type in `vk` as a Key Type;
6. Fill Application ID and Secure Key respectively:

<img src="https://user-images.githubusercontent.com/1666014/35533027-e9352a38-0544-11e8-8590-cf256c00712f.png" width="330">

After these steps, login using VK accounts will be available.

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `code`           | OAuth 2.0 authentication code.                |
| `redurect_uri`   | OAuth 2.0 redirect location.                  |

See <a href="#oauth-20">OAuth 2.0</a> section to how obtain these arguments.

# gamecenter

A way to authenticate using a Apple's Game Center. Please note, this way is only possible on `iOS`.

This way may look complicated, however it can be described in a few steps:

1. Generate <a href="https://developer.apple.com/reference/gamekit/gklocalplayer/1515407-generateidentityverificationsign?language=objc">a signature</a> for the player;
2. At the return, you will have such: `publicKeyUrl`, `signature`, `salt`  and `timestamp`;
3. Pass them respectively as the expected arguments.

After these steps, login using gamecenter accounts will be available.

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `public_key`     | A `publicKeyUrl` returned from generation process |
| `signature`      | A generated `signature` |
| `salt`           | A generated `salt` |
| `timestamp`      | A generated `timestamp` |
| `bundle_id`      | Bundle ID of your Application |
| `username`       | A <a href="https://developer.apple.com/reference/gamekit/gkplayer/1521127-playerid?language=objc">playerID</a> retreived from iOS |

# steam

A way to authenticate using a Steam Account.

To enable this feature, a WebAPI key should be used:

1. Create a <a href="https://partner.steamgames.com/documentation/webapi#creating">WebAPI key</a>;
2. Open the Anthill Admin tool and select the Login service;
3. Select the section "Keys" and click "Add New Key";
4. Select `steam` as a Key Type;
5. Fill Steam Game ID and Encrypted App Ticket Key respectively:

<img src="https://user-images.githubusercontent.com/1666014/35533153-4618bd28-0545-11e8-8c9e-e4a15ca97d72.png" width="330">

After these steps, login using steam accounts will be available.

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `ticket`         | Session ticket <a href="https://partner.steamgames.com/documentation/auth#client_to_backend_webapi">acquired from Steam API</a>        |
| `app_id`         | Application ID (`app_id.txt`) to authenticate for        |

# mailru

A way to authenticate using Mail.Ru Games Service (via @Mail.Ru Launcher).

To enable this feature, a Secret should be used:

1. Create a <a href="https://games.mail.ru/dev/games/">Game Project</a>;
2. Open the Anthill Admin tool and select the Login service;
3. Select the section "Keys" and click "Add New Key";
4. Select `mailru` as a Key Type;
5. Fill Game ID and Secret respectively:

<img src="https://user-images.githubusercontent.com/1666014/35533600-bbd114b0-0546-11e8-956d-de3a66788313.png" width="330">

After these steps, login using Mail.Ru Games accounts will be available.

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `uid`            | UID received from @Mail.Ru Launcher    |
| `hash`           | OTP hash received from @Mail.Ru Launcher        |

# token

A special way to authenticate, using existing token 
(for example, you would like to request more scopes, but don't want to process a full authentication again)

These arguments are expected during <a href="API.md#authenticate">authentication</a>:

| Argument         | Description                                   |
|------------------|-----------------------------------------------|
| `access_token`   | Existing valid access token with the same gamespace as the requested |
