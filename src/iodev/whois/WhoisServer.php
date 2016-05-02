<?php

namespace iodev\whois;

/**
 * @author Sergey Sedyshev
 */
class WhoisServer
{
    /**
     * @param string $topLevelDomain
     * @param string $host
     * @param IWhoisInfoParser $infoParser
     * @return WhoisServer
     */
    public static function createCentralized( $topLevelDomain, $host, IWhoisInfoParser $infoParser )
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
     * @param IWhoisInfoParser $infoParser
     * @return WhoisServer
     */
    public static function createDistributed( $topLevelDomain, $host, IWhoisInfoParser $infoParser )
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
    
    /** @var IWhoisInfoParser */
    public $infoParser;
}
