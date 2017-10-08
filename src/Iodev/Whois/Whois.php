<?php

namespace Iodev\Whois;

use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\InfoParsers\ComInfoParser;
use Iodev\Whois\InfoParsers\RuInfoParser;

class Whois
{
    /**
     * @return Whois
     */
    public static function create()
    {
        return (new Whois())
            ->addServer(Server::createDistributed(".com", "whois.crsnic.net", new ComInfoParser()))
            ->addServer(Server::createDistributed(".net", "whois.crsnic.net", new ComInfoParser()))
            ->addServer(Server::createCentralized(".ru", "whois.ripn.net", new RuInfoParser()))
            ->addServer(Server::createCentralized(".xn--p1ai", "whois.ripn.net", new RuInfoParser()));
    }

    public function __construct()
    {
        $this->loader = new Loader();
        $this->servers = [];
    }
    
    /** @var Loader */
    private $loader;
    
    /** @var Server[] */
    private $servers;
    
    /**
     * @param Server $server
     * @return Whois
     */
    public function addServer(Server $server)
    {
        $this->servers[] = $server;
        return $this;
    }
    
    /**
     * @param string $domain
     * @return Server[]
     */
    public function matchServers($domain)
    {
        $domain = DomainHelper::toAscii($domain);
        $servers = [];
        foreach ($this->servers as $server) {
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
     * @return Info
     */
    public function loadInfo($domain)
    {
        $domain = DomainHelper::toAscii($domain);
        $servers = $this->matchServers($domain);
        foreach ($servers as $server) {
            $info = $this->loader->loadInfo($server, $domain);
            if ($info) {
                return $info;
            }
        }
        return null;
    }
}
