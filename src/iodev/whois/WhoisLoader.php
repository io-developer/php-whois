<?php

namespace iodev\whois;

use Exception;

/**
 * @author Sergey Sedyshev
 */
class WhoisLoader
{
    public function __construct()
    {
        $this->_reponseParser = new WhoisResponseParser();
        $this->_cached = [];
    }
    
    
    /** @var WhoisResponseParser */
    private $_reponseParser;
    
    /** @var string[] */
    private $_cached;
    
        
    /**
     * @param WhoisServer $server
     * @param string $domain
     * @return WhoisInfo
     */
    public function loadInfo( WhoisServer $server, $domain )
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
     * @return WhoisResponse
     */
    public function loadResponse( $whoisHost, $domain, $strict=false )
    {
        $s = $this->loadString($whoisHost, $domain, $strict);
        return $this->_reponseParser->fromString($domain, $s);
    }
    
    /**
     * @param string $whoisHost
     * @param string $domain
     * @return string
     */
    public function loadString( $whoisHost, $domain, $strict=false )
    {
        $cachekey = $whoisHost . ":" . $domain . ":" . (int)$strict;
        if ($this->_cached[$cachekey]) {
            return $this->_cached[$cachekey];
        }
        
        $handle = fsockopen($whoisHost, 43);
        if (!$handle) {
            throw new Exception("Connection error");
        }
        
        fputs($handle, $strict ? "={$domain}\n" : "{$domain}\n");
        
        $s = "";
        while (!feof($handle)) {
            $s .= fgets($handle, 128);
        }
        
        fclose($handle);
        
        $this->_cached[$cachekey] = $s;
        
        return $s;
    }
}
