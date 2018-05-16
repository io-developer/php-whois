# PHP WHOIS

[![Build Status](https://travis-ci.org/io-developer/php-whois.svg?branch=master)](https://travis-ci.org/io-developer/php-whois)
[![PHP version](https://img.shields.io/badge/php-%3E%3D5.4-8892BF.svg)](https://secure.php.net/)
[![Packagist](https://img.shields.io/packagist/v/io-developer/php-whois.svg)](https://packagist.org/packages/io-developer/php-whois)

PHP WHOIS client implementation. Sends queries directly to WHOIS services (via port 43).

## Use case
 * Raw and parsed domain lookup
 * Raw and parsed ASN routes lookup
 * Direct queries to TLD/ASN hosts
 * Extending or customizing default hosts

## Installation

#### Requirements
* PHP >= __5.4__ (compatible with __7.*__ up to __nightly__)
* intl
* mbstring

#### Composer
CLI:
````
composer require io-developer/php-whois
````
Or _composer.json_:
````
"require": {
    "io-developer/php-whois": "^3.0.0"
}
````


## Usage
Ensure your project support PSR class autoloading.

### Domain lookup

##### How to get summary about domain:
```php
<?php

use Iodev\Whois\Whois;

// Creating default configured client
Whois::create();

// Checking availability
if (Whois::create()->isDomainAvailable("google.com")) {
    print "Bingo! Domain is available! :)";
}

// Supports Unicode (converts to punycode)
if (Whois::create()->isDomainAvailable("почта.рф")) {
    print "Bingo! Domain is available! :)";
}

// Getting raw-text lookup
$response = Whois::create()->lookupDomain("google.com");
print $response->getText();

// Getting parsed domain info
$info = Whois::create()->loadDomainInfo("google.com");
print_r([
    'Domain created' => date("Y-m-d", $info->getCreationDate()),
    'Domain expires' => date("Y-m-d", $info->getExpirationDate()),
    'Domain owner' => $info->getOwner(),
]);

```

##### Exceptions on domain lookup:
```php
<?php

use Iodev\Whois\Whois;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;

try {
    $info = Whois::create()->loadDomainInfo("google.com");
    if (!$info) {
        print "Null if domain available";
        exit;
    }
    print $info->getDomainName() . " expires at: " . date("d.m.Y H:i:s", $info->getExpirationDate());
} catch (ConnectionException $e) {
    print "Disconnect or connection timeout";
} catch (ServerMismatchException $e) {
    print "TLD server (.com for google.com) not found in current server hosts";
}
```

##### Сustomize TLD hosts:
```php
<?php

use Iodev\Whois\Whois;
use Iodev\Whois\Modules\Tld\TldServer;
use Iodev\Whois\Modules\Tld\TldParser;

$whois = Whois::create();

// Define custom whois host
$customServer = new TldServer(".custom", "whois.nic.custom", false, TldParser::create());

// Or define the same via assoc way
$customServer = TldServer::fromData([
    "zone" => ".custom",
    "host" => "whois.nic.custom",
]);

// Add custom server to existing whois instance
$whois->getTldModule()->addServers([$customServer]);

// Now it can be utilized
$info = $whois->loadDomainInfo("google.custom");

var_dump($info);
```

### ASN lookup

##### How to get summary using ASN number:
```php
<?php

use Iodev\Whois\Whois;

// Getting raw-text lookup
$response = Whois::create()->lookupAsn("AS32934");
print $response->getText();

// Getting parsed ASN info
$info = Whois::create()->loadAsnInfo("AS32934");
foreach ($info->getRoutes() as $route) {
    print_r([
        'route IPv4' => $route->getRoute(),
        'route IPv6' => $route->getRoute6(),
        'description' => $route->getDescr(),
    ]);   
}

```

### Cached responses
Some TLD hosts are very limited for requests. Use cache if in your case requests are frequently repeating.
```php
<?php

use Iodev\Whois\Whois;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Loaders\MemcachedLoader;

$m = new Memcached();
$m->addServer('127.0.0.1', 11211);
$loader = new MemcachedLoader(new SocketLoader(), $m);

$whois = Whois::create($loader);
```

