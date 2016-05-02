# PHP Whois API
PHP library requesting (via socket port 43) and parsing real WHOIS service responses.

## Requirements
PHP >= 5.4
- intl


## Usage

### Creating whois instance for common top-level domains (.com, .net, .ru, .рф)

```php
use iodev\whois\Whois;

$whois = Whois::create();
```

### Loading domain info

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

### Getting original whois text response

```php
/**
 * @var $info \iodev\whois\WhoisInfo
 *
 * $info->domainName         Real domain name (punycode)
 * $info->domainNameUnicode  Domain name in unicode (decoded punycode)
 * $info->nameServers        List of name servers
 * $info->creationDate       Unixtime creation date
 * $info->expirationDate     Unixtime expiration date
 * $info->states             Status list in upper-case
 * $info->owner              Owner (company) name
 * $info->registrar          Registrar name
 * $info->response           \iodev\whois\WhoisResponse
 *                           containing original whois response text and parsed grouped key-value pairs.
 */
$info = $whois->loadInfo("google.com");
$response = $info->response;

echo "WHOIS response for '{$response->requestedDomain}':\n{$response->content}";
```

### Adding custom whois server

```php
use iodev\whois\WhoisServer;
use iodev\whois\parsers\ComInfoParser;

$edu = new WhoisServer();
$edu->isCentralized = false;
$edu->topLevelDomain = ".edu";
$edu->host = "whois.crsnic.net";
$edu->infoParser = new ComInfoParser();

// Or via static factory method
$edu = WhoisServer::createDistributed(".edu", "whois.crsnic.net", new ComInfoParser());

// Attaching
$whois->addServer($edu);
```


## Try example to check it out

```php
<?php

use iodev\whois\Whois;


// Including autoload file if needing
require_once $_SERVER['DOCUMENT_ROOT'] . "/replace-this-by-the-lib-path/iodev/whois/autoload.php";

// Creating default instance for top-level domains: .com .net .ru .рф
$whois = Whois::create();

// Dumping domain info

var_dump($whois->loadInfo("google.com"));
var_dump($whois->loadInfo("google.ru"));
var_dump($whois->loadInfo("php.net"));
var_dump($whois->loadInfo("speedtest.net"));
var_dump($whois->loadInfo("почта.рф"));
```
