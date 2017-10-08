<?php

namespace Iodev\Whois;

use RuntimeException;

class Loader
{
    public function __construct()
    {
        $this->cache = [];
    }

    /** @var string[] */
    private $cache;

    /**
     * @param Server $server
     * @param string $domain
     * @return Info
     */
    public function loadInfo(Server $server, $domain)
    {
        $p = $server->infoParser;
        $r = $this->loadResponse($server->host, $domain);
        $info = $p->fromResponse($r);
        if (!$info) {
            $r = $this->loadResponse($server->host, $domain, true);
            $info = $p->fromResponse($r);
        }
        if ($info && $info->whoisServer && !$server->isCentralized) {
            try {
                $r = $this->loadResponse($info->whoisServer, $domain);
                $tmpInfo = $p->fromResponse($r);
                $info = $tmpInfo ? $tmpInfo : $info;
            } catch (Exception $err) {
                
            }
        }
        return $info;
    }
    
    /**
     * @param string $whoisHost
     * @param string $domain
     * @param bool $strict
     * @return Response
     */
    public function loadResponse($whoisHost, $domain, $strict = false)
    {
        return Response::fromString($domain, $this->loadString($whoisHost, $domain, $strict));
    }
    
    /**
     * @param string $whoisHost
     * @param string $domain
     * @param bool $strict
     * @return string
	 * @throws RuntimeException
     */
    public function loadString($whoisHost, $domain, $strict = false)
    {
        $key = $whoisHost . ":" . $domain . ":" . (int)$strict;
        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }
        
        $handle = fsockopen($whoisHost, 43);
        if (!$handle) {
            throw new RuntimeException("Could not open socket (port 43)");
        }
        
        fputs($handle, $strict ? "={$domain}\n" : "{$domain}\n");
        $content = "";
        while (!feof($handle)) {
            $content .= fgets($handle, 128);
        }
        fclose($handle);
        $this->cache[$key] = $content;
        
        return $content;
    }
}
