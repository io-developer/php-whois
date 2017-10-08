<?php

namespace Iodev\Whois;

use Iodev\Whois\InfoParsers\IInfoParser;

class Server
{
    /**
     * @param string $topLevelDomain
     * @param string $host
     * @param IInfoParser $infoParser
     * @return Server
     */
    public static function createCentralized($topLevelDomain, $host, IInfoParser $infoParser)
    {
        $s = new Server();
        $s->isCentralized = true;
        $s->topLevelDomain = $topLevelDomain;
        $s->host = $host;
        $s->infoParser = $infoParser;
        return $s;
    }
    
    /**
     * @param string $topLevelDomain
     * @param string $host
     * @param IInfoParser $infoParser
     * @return Server
     */
    public static function createDistributed($topLevelDomain, $host, IInfoParser $infoParser)
    {
        $s = new Server();
        $s->isCentralized = false;
        $s->topLevelDomain = $topLevelDomain;
        $s->host = $host;
        $s->infoParser = $infoParser;
        return $s;
    }
    
    /** @var bool */
    public $isCentralized;
    
    /** @var string */
    public $host;
    
    /** @var string */
    public $topLevelDomain;
    
    /** @var IInfoParser */
    public $infoParser;
}
