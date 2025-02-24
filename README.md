# phpasskey

Concise passkey authentication for php with mysql. Only uses cookies once the login process begins.

## Setup

Create the following table.

```sql
CREATE TABLE `passkeys` (
  `passkey` varbinary(32) PRIMARY KEY,
  `alg` smallint,
  `pub` varbinary(294),
  `user` int,
  `label` varchar(64)
)
```

Add this to the top of any php file that requires login. You can customize the login screen to your liking where the login button is echoed.

```php
<?php

$mySQLi = new mysqli('server', 'user', 'password', 'database'); // TODO
(!$mySQLi->connect_error) or exit('mySQLi unable to connect');
$mySQLi->set_charset('utf8mb4');
register_shutdown_function(fn() => $mySQLi->close());

(require 'phpasskey.php')(function() {
  // Only continues if not already logged in.
  echo '<button onclick="login()">Login</button>';
}, $mySQLi, register: 'passkey label');
// Only continues if the user is logged in.
echo '<button onclick="register()">Register</button>';
```

If the above is put in a php file you can require it in other files to reuse a login screen. Passkey registration is only possible if the user is logged in and the passkey label is not omitted. You may login by setting the following session variables.

```php
<?php
session_start();
$_SESSION['user'] = 1;
$_SESSION['name'] = 'John Doe';
```

## Notes

* Some variables are base64 decoded just to encode them. This prevents missing base64 padding.
* Microsoft Hello replaces `+` and `/` with `-` and `_` to allow url encoding.
* The header of Microsoft Hello public keys is replaced with MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A. There was an `s` instead of an `E`.
