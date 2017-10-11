<?php

namespace Iodev\Whois;

use Iodev\Whois\Parsers\IParser;

class Server
{
    /**
      * @param string $zone
     */
    public function __construct($zone)
    {
        $this->zone = $zone;
    }

    /** @var string */
    public $zone;

    /** @var string */
    public $host;

    /** @var bool */
    public $isCentralized;
    
    /** @var IParser */
    public $parser;
}
