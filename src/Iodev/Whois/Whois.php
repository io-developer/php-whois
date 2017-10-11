<?php

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Helpers\DomainHelper;

class Whois
{
    /**
     * @param null $servers
     * @param Loader|null $loader
     * @return Whois
     */
    public static function create($servers = null, Loader $loader = null)
    {
        $servers = isset($servers) ? $servers : ServerFactory::createAll();
        $loader = $loader ? $loader : new Loader();

        $whois = new Whois($loader);
        foreach ($servers as $server) {
            $whois->addServer($server);
        }

        return $whois;
    }

    public function __construct(Loader $loader)
    {
        $this->loader = $loader;
    }
    
    /** @var Loader */
    private $loader;
    
    /** @var Server[] */
    private $servers = [];

    /** @var string[] */
    private $cache = [];
    
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
        $parser = $server->parser;
        $resp = $this->loadResponseFrom($server->host, $domain);
        $info = $parser->parseResponse($resp);
        if (!$info) {
            $resp = $this->loadResponseFrom($server->host, $domain, true);
            $info = $parser->parseResponse($resp);
        }
        if ($info && $info->whoisServer && !$server->isCentralized) {
            $resp = $this->loadResponseFrom($info->whoisServer, $domain);
            $tmpInfo = $parser->parseResponse($resp);
            $info = $tmpInfo ? $tmpInfo : $info;
        }
        return $info;
    }

    /**
     * @param string $whoisHost
     * @param string $domain
     * @param bool $strict
     * @return Response
     */
    public function loadResponseFrom($whoisHost, $domain, $strict = false)
    {
        $key = $whoisHost . ":" . $domain . ":" . (int)$strict;
        if (isset($this->cache[$key])) {
            $text = $this->cache[$key];
        } else {
            $text = $this->cache[$key] = $this->loader->loadText($whoisHost, $domain, $strict);
        }
        return new Response($domain, $text);
    }

    /**
     * @return $this
     */
    public function clearCache()
    {
        $this->cache = [];
        return $this;
    }
}
