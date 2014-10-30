Tc JOSE
=======

[![Build Status](https://travis-ci.org/carlcraig/tc-jose.svg)](https://travis-ci.org/carlcraig/tc-jose)
[![Latest Stable Version](https://poser.pugx.org/tc/jose/v/stable.svg)](https://packagist.org/packages/tc/jose) [![License](https://poser.pugx.org/tc/jose/license.svg)](https://packagist.org/packages/tc/jose)

#### A Javascript Object Signing and Encryption Library


Installation
------------

Using composer, add the following to your `composer.json`:

```json
"tc/jose": "dev-master"
```

You could also run:

```sh
$ php composer.phar require tc/jose "dev-master"
```

Supported Algorithms
--------------------

- None
- HS256, HS384, HS512
- RS256, RS384, RS512
- ES256, ES384, ES512


Creating a JWS
--------------

To create a JWS you would do something like this:

```php
<?php

use Tc\JOSE\JWS;

// ...

// Create a new JWS
$jws = new JWS();

// Add some data to the payload
$jws->setPayload(array(
    'user' => 'SomeUser'
));

// Set Issued At Claim
$jws->setIssuedAt();

// Set Expires for 1 hour
$jws->setExpires(3600);

// Sign the JWS (Can use any of the supported algorithms)
$jws->sign('HS256', 'SecretKeyHere');

// Serialize the JWS to be transported
$jwsSerialized = $jws->serialize();

// Should look like:
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpPU0UifQ.e30.ssb8sFTv7UK37oW395EUkSL9g8uNPDhMHFvRwcUenXo

// You could then return this token to the client normally or as a header/cookie

// ...

```

Decoding a Serialized JWT *(JWS or JWE)*
----------------------------------------

```php
<?php

use Tc\JOSE\JWT;
use Tc\JOSE\JWS;

// ...

// The Serialized JWT (could be from a header/request parameter)
$jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpPU0UifQ.e30.ssb8sFTv7UK37oW395EUkSL9g8uNPDhMHFvRwcUenXo';

// Try to decode the Serialized JWT
try {

    $decodedJWT = JWT::decode($jwt);
    
    // Check if the decoded JWT is a JWS (could potentially be a JWS or JWE)
    if ( $decodedJWT instanceof JWS ) {
    
        // is a JWS, we now check it is valid
        $isValid = $decodedJWT->validate('SecretKeyHere');
        
        if ($isValid) {
            // JWS is valid
        }
        
    }
} catch(InvalidArgumentException $e) {
    // Invalid JWT, handle here
}

// ...

```

Using RS or ES Algorithms
-------------------------

#### Create the keys with openssl

You can adjust the format for creating the keys to work with ES or RS.

```sh
$ openssl genrsa -out private.pem -aes256 4096
$ openssl rsa -pubout -in private.pem -out public.pem
```

#### Signing a JWS

```php
<?php

// ...
$jws = new JWS();
$jws->sign('RS256', openssl_pkey_get_private('path/to/privatekey.pem', 'passphrase'));
// ...
```

#### Validate a JWS

```php
<?php

// ...
$jws->validate(openssl_pkey_get_public('path/to/publickey.pem'));
// ...
```

TODO
----

Implement JWE and JWK specifications.


License
-------

tc-jose is licensed with the MIT license.

See LICENSE for more details.
