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
    "io-developer/php-whois": "^1.2.0"
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
$info = $whois->loadInfo("google.com");
if ($info) {
    echo $info->domainName . " expires at: " . date("d.m.Y H:i:s", $info->expirationDate);
    var_dump($info);
} else {
    echo "Domain is available!";
}
```

#### 3. Getting original whois text response

```php
$info = $whois->loadInfo("google.com");
$resp = $info->response;

echo "WHOIS response for '{$resp->domain}':\n{$resp->text}";
```

#### 4. Using custom whois server (for example is .edu)

```php
use Iodev\Whois\Server;
use Iodev\Whois\Parsers\ComParser;

$edu = new Server();
$edu->isCentralized = false;
$edu->zone = ".edu";
$edu->host = "whois.crsnic.net";
$edu->parser = new ComParser();

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
