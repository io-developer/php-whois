# PHP WHOIS
PHP library provides parsed WHOIS domain information. Easy way to check domain availability or expiration date. Implements requests to real WHOIS service via port 43.

[![Build Status](https://travis-ci.org/io-developer/php-whois.svg?branch=master)](https://travis-ci.org/io-developer/php-whois)

## Requirements
- PHP >= 5.4
- intl

## Installing
````
composer require io-developer/php-whois
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

$edu = new Server(".edu");
$edu->isCentralized = false;
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
var_dump($whois->loadInfo("speedtest.net.txt"));
var_dump($whois->loadInfo("почта.рф"));
```
