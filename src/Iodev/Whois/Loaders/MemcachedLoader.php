<?php

namespace Iodev\Whois\Loaders;

use Iodev\Whois\AsnResponse;
use Memcached;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Response;

class MemcachedLoader implements ILoader
{
    public function __construct(ILoader $l, Memcached $m, $keyPrefix = "", $ttl = 3600)
    {
        $this->loader = $l;
        $this->memcached = $m;
        $this->keyPrefix = $keyPrefix;
        $this->ttl = $ttl;
    }

    /** @var ILoader */
    private $loader;

    /** @var Memcached */
    private $memcached;

    /** @var string */
    private $keyPrefix;

    /** @var int */
    private $ttl;

    /**
     * @param string $whoisHost
     * @param string $domain
     * @param bool $strict
     * @return Response
     * @throws ConnectionException
     */
    public function loadResponse($whoisHost, $domain, $strict = false)
    {
        $key = $this->keyPrefix . md5(serialize([$whoisHost, $domain, $strict]));
        $val = $this->memcached->get($key);
        if ($val) {
            return unserialize($val);
        }
        $val = $this->loader->loadResponse($whoisHost, $domain, $strict);
        $this->memcached->set($key, serialize($val), $this->ttl);
        return $val;
    }

    /**
     * @param string $whoisHost
     * @param string $asn
     * @return AsnResponse
     * @throws ConnectionException
     */
    public function loadAsnResponse($whoisHost, $asn)
    {
        $key = $this->keyPrefix . md5(serialize([$whoisHost, $asn]));
        $val = $this->memcached->get($key);
        if ($val) {
            return unserialize($val);
        }
        $val = $this->loader->loadAsnResponse($whoisHost, $asn);
        $this->memcached->set($key, serialize($val), $this->ttl);
        return $val;
    }
}
