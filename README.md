# PHP WHOIS

[![PHP version](https://img.shields.io/badge/php-%3E%3D7.2-8892BF.svg)](https://secure.php.net/)
[![Packagist](https://img.shields.io/packagist/v/io-developer/php-whois.svg)](https://packagist.org/packages/io-developer/php-whois)

PHP WHOIS client implementation. Sends the queries directly to the WHOIS services.

## Use case
 * Raw and parsed domain lookup
 * Raw and parsed ASN routes lookup
 * Direct queries to TLD/ASN hosts
 * Extending and customizing the default hosts, parsers, etc.
 * Proxying via CurlLoader

## Installation

##### System requirements:
* PHP >= __7.2__ (old versions supports __5.4+__)
* php-curl
* php-mbstring
* Open port __43__ in firewall

Optional:
* php-intl
* php-memcached + Memcached server

##### Project requirements:
* PSR-4 autoloader

##### Composer:
````
composer require io-developer/php-whois
````
or composer.json:
````
"require": {
    "io-developer/php-whois": "^4.0"
}
````


## Usage

### Domain lookup

##### How to get summary about domain:
```php
<?php

use Iodev\Whois\Factory;

// Creating default configured client
$whois = Factory::get()->createWhois();

// Checking availability
if ($whois->isDomainAvailable("google.com")) {
    print "Bingo! Domain is available! :)";
}

// Supports Unicode (converts to punycode)
if ($whois->isDomainAvailable("почта.рф")) {
    print "Bingo! Domain is available! :)";
}

// Getting raw-text lookup
$response = $whois->lookupDomain("google.com");
print $response->text;

// Getting parsed domain info
$info = $whois->loadDomainInfo("google.com");
print_r([
    'Domain created' => date("Y-m-d", $info->creationDate),
    'Domain expires' => date("Y-m-d", $info->expirationDate),
    'Domain owner' => $info->owner,
]);

```

##### Exceptions on domain lookup:
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;

try {
    $whois = Factory::get()->createWhois();
    $info = $whois->loadDomainInfo("google.com");
    if (!$info) {
        print "Null if domain available";
        exit;
    }
    print $info->domainName . " expires at: " . date("d.m.Y H:i:s", $info->expirationDate);
} catch (ConnectionException $e) {
    print "Disconnect or connection timeout";
} catch (ServerMismatchException $e) {
    print "TLD server (.com for google.com) not found in current server hosts";
} catch (WhoisException $e) {
    print "Whois server responded with error '{$e->getMessage()}'";
}
```

##### Proxy with SOCKS5:
```php
<?php

use Iodev\Whois\Loaders\CurlLoader;
use Iodev\Whois\Factory;

$loader = new CurlLoader();
$loader->replaceOptions([
    CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5,
    CURLOPT_PROXY => "127.0.0.1:1080",
    //CURLOPT_PROXYUSERPWD => "user:pass",
]);
$whois = Factory::get()->createWhois($loader);

var_dump([
    'ya.ru' => $whois->loadDomainInfo('ya.ru'),
    'google.de' => $whois->loadDomainInfo('google.de'),
]);
```

##### TLD hosts customization:
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Modules\Tld\TldServer;

$whois = Factory::get()->createWhois();

// Define custom whois host
$customServer = new TldServer(".custom", "whois.nic.custom", false, Factory::get()->createTldParser());

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

##### TLD default/fallback servers:
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Modules\Tld\TldServer;

$whois = Factory::get()->createWhois();

// Add default servers
$matchedServers = $whois->getTldModule()
    ->addServers(TldServer::fromDataList([
        ['zone' => '.*.net', 'host' => 'localhost'],
        ['zone' => '.uk.*', 'host' => 'localhost'],
        ['zone' => '.*', 'host' => 'localhost'],
    ]))
    ->matchServers('some.uk.net');

foreach ($matchedServers as $s) {
    echo "{$s->getZone()}  {$s->getHost()}\n";
}

// Matched servers + custom defaults:
//
// .uk.net  whois.centralnic.com
// .uk.net  whois.centralnic.net
// .uk.*  localhost
// .*.net  localhost
// .net  whois.crsnic.net
// .net  whois.verisign-grs.com
// .*  localhost
```

### ASN lookup

##### How to get summary using ASN number:
```php
<?php

use Iodev\Whois\Factory;

$whois = Factory::get()->createWhois();

// Getting raw-text lookup
$response = $whois->lookupAsn("AS32934");
print $response->text;

// Getting parsed ASN info
$info = $whois->loadAsnInfo("AS32934");
foreach ($info->routes as $route) {
    print_r([
        'route IPv4' => $route->route,
        'route IPv6' => $route->route6,
        'description' => $route->descr,
    ]);   
}

```

### Response caching
Some TLD hosts are very limited for frequent requests. Use cache if in your case requests are repeating.
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Loaders\MemcachedLoader;

$m = new Memcached();
$m->addServer('127.0.0.1', 11211);
$loader = new MemcachedLoader(new SocketLoader(), $m);

$whois = Factory::get()->createWhois($loader);
// do something...
```


## Develompment
Supported php versions are configured in `docker-compose.yml`

Common use cases:
1. Set up & run all tests: `docker compose up --build`
2. Run tests under specific php version: `docker compose up php-8.2_intl --build`
3. Run scripts: `docker compose run php-8.2_intl bin/php-whois info google.com`

Also see **TESTS.md**


## Contributing

The project is open for pull requests, issues and feedback. Please read the CODE_OF_CONDUCT.md
