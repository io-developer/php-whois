<?php

namespace Iodev\Whois;

use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Parsers\IParser;

class Server
{
    public function __construct($zone, $centralized, $host, IParser $parser)
    {
        $this->zone = strval($zone);
        $this->centralized = (bool)$centralized;
        $this->host = strval($host);
        $this->parser = $parser;
    }

    /** @var string */
    private $zone;

    /** @var bool */
    private $centralized;

    /** @var string */
    private $host;
    
    /** @var IParser */
    private $parser;

    /**
     * @return bool
     */
    public function isCentralized()
    {
        return (bool)$this->centralized;
    }

    /**
     * @param string $domain
     * @return bool
     */
    public function isDomainZone($domain)
    {
        return DomainHelper::belongsToZone($domain, $this->zone);
    }

    /**
     * @return string
     */
    public function getZone()
    {
        return $this->zone;
    }

    /**
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * @return IParser
     */
    public function getParser()
    {
        return $this->parser;
    }
}
