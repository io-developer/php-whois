<?php

return [
    [
        'zone' => '.com',
        'host' => 'whois.crsnic.net',
        'centralized' => false,
        'parser' => '\Iodev\Whois\Parsers\ComParser',
    ], [
        'zone' => '.net',
        'host' => 'whois.crsnic.net',
        'centralized' => false,
        'parser' => '\Iodev\Whois\Parsers\RuParser',
    ], [
        'zone' => '.ru',
        'host' => 'whois.ripn.net',
        'centralized' => true,
        'parser' => '\Iodev\Whois\Parsers\RuParser',
    ], [
        // .рф
        'zone' => '.xn--p1ai',
        'host' => 'whois.ripn.net',
        'centralized' => true,
        'parser' => '\Iodev\Whois\Parsers\RuParser',
    ],
];
