# PHP WHOIS client
PHP library implements requests to real WHOIS service (via port 43) and provides parsed info.

## Requirements
PHP >= 5.4
- intl

## Installing with Composer
#### Run cli command
````
composer require io-developer/php-whois
````
#### Or edit composer.json
````
"require": {
    "io-developer/php-whois": "^1.1.0"
}
````
_Optional:_ add repository if needed
````
"repositories": [
    {
        "type": "vcs",
        "url": "https://github.com/io-developer/php-whois"
    }
]
````



## Usage

#### 1. Creating common Whois client (.com .net .ru .рф)

```php
use Iodev\Whois\Whois;

require_once '../vendor/autoload.php';

$whois = Whois::create();
```

#### 2. Loading domain info

```php
/**
 * Returns null if
 * domain info not loaded
 * or domain not found
 * or domain not supported by current whois servers
 */
$info = $whois->loadInfo("google.com");

echo $info->domainName . " expiring at: " . date("d.m.Y H:i:s", $info->expirationDate);

var_dump($info);
```

#### 3. Getting original whois text response

```php
$info = $whois->loadInfo("google.com");
$resp = $info->response;

echo "WHOIS response for '{$resp->requestedDomain}':\n{$resp->content}";
```

#### 4. Using custom whois server (for example is .edu)

```php
use Iodev\Whois\Server;
use Iodev\Whois\InfoParsers\ComInfoParser;

$edu = new Server();
$edu->isCentralized = false;
$edu->topLevelDomain = ".edu";
$edu->host = "whois.crsnic.net";
$edu->infoParser = new ComInfoParser();

// Or via static factory method
$edu = Server::createDistributed(".edu", "whois.crsnic.net", new ComInfoParser());

// Attaching
$whois->addServer($edu);

// Now you can load info about *.edu domain
$whois->loadInfo("some.edu");
```


## Example

```php
<?php

use Iodev\Whois\Whois;

require_once '../vendor/autoload.php';

$whois = Whois::create();

var_dump($whois->loadInfo("google.com"));
var_dump($whois->loadInfo("google.ru"));
var_dump($whois->loadInfo("php.net"));
var_dump($whois->loadInfo("speedtest.net"));
var_dump($whois->loadInfo("почта.рф"));
```
