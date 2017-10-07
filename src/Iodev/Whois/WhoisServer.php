<?php

namespace Iodev\Whois;

use Iodev\Whois\InfoParsers\IInfoParser;

class WhoisServer
{
    /**
     * @param string $topLevelDomain
     * @param string $host
     * @param IInfoParser $infoParser
     * @return WhoisServer
     */
    public static function createCentralized($topLevelDomain, $host, IInfoParser $infoParser)
    {
        $s = new WhoisServer();
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
     * @return WhoisServer
     */
    public static function createDistributed($topLevelDomain, $host, IInfoParser $infoParser)
    {
        $s = new WhoisServer();
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
