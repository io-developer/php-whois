<?php

namespace Iodev\Whois;

use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Parsers\IParser;

class Server
{
    /**
      * @param string $zone
     */
    public function __construct($zone, $centralized, $host, IParser $parser)
    {
        $this->zone = $zone;
        $this->isCentralized = $centralized;
        $this->host = $host;
        $this->parser = $parser;
    }

    /** @var string */
    private $zone;

    /** @var string */
    private $host;

    /** @var bool */
    private $isCentralized;
    
    /** @var IParser */
    private $parser;

    /**
     * @return bool
     */
    public function isCentralized()
    {
        return (bool)$this->isCentralized;
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
