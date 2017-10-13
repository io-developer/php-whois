<?php

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Loaders\SocketLoader;

class Whois
{
    /**
     * @param Server[] $servers
     * @param ILoader $loader
     * @return Whois
     */
    public static function create($servers = null, ILoader $loader = null)
    {
        $whois = new Whois($loader ? $loader : new SocketLoader());
        $servers = isset($servers) ? $servers : ServerFactory::createAll();
        foreach ($servers as $server) {
            $whois->addServer($server);
        }
        return $whois;
    }

    public function __construct(ILoader $loader)
    {
        $this->loader = $loader;
    }
    
    /** @var ILoader */
    private $loader;
    
    /** @var Server[] */
    private $servers = [];
    
    /**
     * @param Server $server
     * @return $this
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
            $tld = $server->zone;
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
     * @throws ServerMismatchException
     */
    public function loadInfo($domain)
    {
        $domain = DomainHelper::toAscii($domain);
        $servers = $this->matchServers($domain);
        if (empty($servers)) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }
        foreach ($servers as $server) {
            $info = $this->loadInfoFrom($server, $domain);
            if ($info) {
                return $info;
            }
        }
        return null;
    }

    /**
     * @param Server $server
     * @param string $domain
     * @return Info
     */
    public function loadInfoFrom(Server $server, $domain)
    {
        $l = $this->loader;
        $p = $server->parser;
        $info = $p->parseResponse($l->loadResponse($server->host, $domain));
        if (!$info) {
            $info = $p->parseResponse($l->loadResponse($server->host, $domain, true));
        }
        if ($info && $info->whoisServer && !$server->isCentralized) {
            $tmpInfo = $p->parseResponse($l->loadResponse($info->whoisServer, $domain));
            $info = $tmpInfo ? $tmpInfo : $info;
        }
        return $info;
    }
}
