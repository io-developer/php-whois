<?php

namespace iodev\whois;

use iodev\whois\helpers\DomainHelper;
use iodev\whois\parsers\ComInfoParser;
use iodev\whois\parsers\RuInfoParser;

/**
 * @author Sergey Sedyshev
 */
class Whois
{
    /**
     * @return Whois
     */
    public static function create()
    {
        return (new Whois())
            ->addServer(WhoisServer::createDistributed(".com", "whois.crsnic.net", new ComInfoParser()))
            ->addServer(WhoisServer::createDistributed(".net", "whois.crsnic.net", new ComInfoParser()))
            ->addServer(WhoisServer::createCentralized(".ru", "whois.ripn.net", new RuInfoParser()))
            ->addServer(WhoisServer::createCentralized(".xn--p1ai", "whois.ripn.net", new RuInfoParser()));
    }
    
    /**
     * 
     */
    public function __construct()
    {
        $this->_loader = new WhoisLoader();
        $this->_servers = [];
    }
    
    
    /** @var WhoisLoader */
    private $_loader;
    
    /** @var WhoisServer[] */
    private $_servers;
    
    
    /**
     * @param WhoisServer $server
     * @return Whois
     */
    public function addServer( WhoisServer $server )
    {
        $this->_servers[] = $server;
        return $this;
    }
    
    /**
     * @param string $domain
     * @return WhoisServer[]
     */
    public function matchServers( $domain )
    {
        $domain = DomainHelper::toAscii($domain);
        $servers = [];
        foreach ($this->_servers as $server) {
            $tld = $server->topLevelDomain;
            $pos = mb_strpos($domain, $tld);
            if ($pos !== false && $pos == (mb_strlen($domain) - mb_strlen($tld))) {
                $servers[] = $server;
            }
        }
        return $servers;
    }
    
    /**
     * @param string $domain
     * @return WhoisInfo
     */
    public function loadInfo( $domain )
    {
        $domain = DomainHelper::toAscii($domain);
        $servers = $this->matchServers($domain);
        foreach ($servers as $server) {
            $info = $this->_loader->loadInfo($server, $domain);
            if ($info) {
                return $info;
            }
        }
        return null;
    }
}
