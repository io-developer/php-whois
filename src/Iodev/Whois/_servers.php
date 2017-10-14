<?php

return [
    [ 'zone' => '.com', 'host' => 'whois.crsnic.net' ],
    [ 'zone' => '.net', 'host' => 'whois.crsnic.net' ],
    [ 'zone' => '.ru', 'host' => 'whois.ripn.net', 'parser' => '\Iodev\Whois\Parsers\RuParser' ],

    // .рф
    [ 'zone' => '.xn--p1ai', 'host' => 'whois.ripn.net', 'parser' => '\Iodev\Whois\Parsers\RuParser' ],
];
