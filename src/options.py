
from common.options import define

# Main

define("host",
       default="http://localhost:9501",
       help="Public hostname of this service",
       type=str)

define("listen",
       default="port:9501",
       help="Socket to listen. Could be a port number (port:N), or a unix domain socket (unix:PATH)",
       type=str)

define("name",
       default="login",
       help="Service short name. Used to discover by discovery service.",
       type=str)

# MySQL database

define("db_host",
       default="127.0.0.1",
       type=str,
       help="MySQL database location")

define("db_username",
       default="root",
       type=str,
       help="MySQL account username")

define("db_password",
       default="",
       type=str,
       help="MySQL account password")

define("db_name",
       default="dev_login",
       type=str,
       help="MySQL database name")

# Primary access token key/value database

define("tokens_host",
       default="127.0.0.1",
       help="Location of primary access token key/value database (redis).",
       group="tokens",
       type=str)

define("tokens_port",
       default=6379,
       help="Port of primary access token key/value database (redis).",
       group="tokens",
       type=int)

define("tokens_db",
       default=1,
       help="Database of primary access token key/value database (redis).",
       group="tokens",
       type=int)

define("tokens_max_connections",
       default=500,
       help="Maximum connections to the primary access token key/value database (connection pool).",
       group="tokens",
       type=int)

# Regular cache

define("cache_host",
       default="127.0.0.1",
       help="Location of a regular cache (redis).",
       group="cache",
       type=str)

define("cache_port",
       default=6379,
       help="Port of regular cache (redis).",
       group="cache",
       type=int)

define("cache_db",
       default=7,
       help="Database of regular cache (redis).",
       group="cache",
       type=int)

define("cache_max_connections",
       default=500,
       help="Maximum connections to the regular cache (connection pool).",
       group="cache",
       type=int)

# Keys

define("application_keys_secret",
       default="7Pr0MtA8hHTmFeR6SOk87NSBvRM4QoCp",
       help="A secret password to decode keys stored in database.",
       type=str)

define("auth_key_private",
       default="../.anthill-keys/anthill.pem",
       help="Location of private key required for access token signing (encrypted).",
       type=str)

define("private_key_password",
       default="wYrA9O187G71ILmZr67GZG945SgarS4K",
       help="A secret paraphrase to decode private key (auth_key_private)",
       type=str)

define("passwords_salt",
       default="t6YJbMTvMRnYyPW7WfZC2tGXUsJwy252pU0OiCM5",
       help="A salt to the passwords stored in the database. Once set should never be changed, "
            "or the users will lost their accounts.",
       type=str)
