# phpasskey

Concise passkey authentication for php with mysql. Only uses cookies once the login process begins.

## Setup

Adjust the mysql credentials at the beginning of the file and create the following table.

```sql
CREATE TABLE `passkeys` (
  `passkey` varbinary(32) PRIMARY KEY,
  `alg` smallint,
  `pub` varbinary(294),
  `user` int,
  `label` varchar(64)
)
```

Once you modified the login page and domain and username logic to your liking (marked with TODO) any php file can require a login by starting with:

```php
<?php
require('phpasskey.php`);
login();
// Only continues if the user is logged in.
```

The option to register a key can be enabled by continuing with `register()`, outputting `phpasskey_js()` in the `head` and adding a button that calls the JavaScript function `register()`. Close the MYSQL connection and end execution with `close()`.

## Notes

* Some variables are base64 decoded just to encode them. This prevents missing base64 padding.
* Microsoft Hello replaces `+` and `/` with `-` and `_` to allow url encoding.
* The header of Microsoft Hello public keys is replaced with MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A. There was an `s` instead of an `E`.
