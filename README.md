# PHP WHOIS
PHP library provides parsed WHOIS domain information. Easy way to check domain availability or expiration date. Implements requests to real WHOIS service via port 43.

[![Travis](https://img.shields.io/travis/io-developer/php-whois.svg?style=flat-square)](https://travis-ci.org/io-developer/php-whois)
[![PHP version](https://img.shields.io/badge/php-%3E%3D5.4-blue.svg?style=flat-square)](https://secure.php.net/)
[![Packagist](https://img.shields.io/packagist/v/io-developer/php-whois.svg?style=flat-square)](https://packagist.org/packages/io-developer/php-whois)
[![license](https://img.shields.io/github/license/io-developer/php-whois.svg?style=flat-square)](https://github.com/io-developer/php-whois/blob/master/LICENSE.md)


## Requirements
- PHP >= 5.4
- intl


## Installing
#### Via Composer cli command
````
composer require io-developer/php-whois
````
#### Or via composer.json
````
"require": {
    "io-developer/php-whois": "^2.0.0"
}
````


## Example: info about google.com

```php
<?php

require_once '../vendor/autoload.php';

use Iodev\Whois\Whois;

$info = Whois::create()->loadInfo("google.com");
echo "Domain created: " . date("Y-m-d", $info->getCreationDate());
echo "Domain expires: " . date("Y-m-d", $info->getExpirationDate());
echo "Domain owner: " . $info->getOwner();
```


## Example: domain availability

```php
<?php

use Iodev\Whois\Whois;

$info = Whois::create()->loadInfo("google.com");
if (!$info) {
    echo "Bingo! Domain is available! :)";
}
```


## Usage

#### 1. Common Whois client

```php
<?php

use Iodev\Whois\Whois;

$whois = Whois::create();
```

#### 1.1. With memcached
```php
<?php

use Iodev\Whois\Whois;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Loaders\MemcachedLoader;

$m = new Memcached();
$m->addServer('127.0.0.1', 11211);
$loader = new MemcachedLoader(new SocketLoader(), $m);

$whois = Whois::create(null, $loader);
```

#### 2. Domain info loading

```php
<?php

use Iodev\Whois\Whois;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;

$whois = Whois::create();
try {
    $info = $whois->loadInfo("google.com");
    if (!$info) {
        echo "Null if domain available";
        exit;
    }
    echo $info->getDomainName() . " expires at: " . date("d.m.Y H:i:s", $info->getExpirationDate());
} catch (ConnectionException $e) {
    echo "Disconnect or connection timeout";
} catch (ServerMismatchException $e) {
    echo "Domain zone servers (.com for google.com) not found in current ServerProvider whois hosts";
}
```

#### 3. Whois text response from info

```php
<?php

use Iodev\Whois\Whois;

$info = Whois::create()->loadInfo("google.com");
$resp = $info->getResponse();

echo "WHOIS response for '{$resp->getDomain()}':\n{$resp->getText()}";
```

#### 4. Custom whois hosts

```php
<?php

use Iodev\Whois\Server;
use Iodev\Whois\Whois;
use Iodev\Whois\Parsers\CommonParser;

$whois = Whois::create();

// Define custom whois host
$customServer = new Server(".co", "whois.nic.co", false, new CommonParser());

// Or define the same via assoc way
$customServer = Server::fromData([
    "zone" => ".co",
    "host" => "whois.nic.co",
]);

// Append to existing provider
$whois->getServerProvider()->addOne($customServer);

// Now you can load info
$info = $whois->loadInfo("google.co");

var_dump($info);
```
