<?php

namespace Iodev\Whois;

class ServerProvider
{
    /**
     *  @param Server[] $servers
     */
    public function __construct($servers)
    {
        $this->add($servers);
    }

    /** @var Server[] */
    private $servers = [];

    /**
     * @param Server $server
     * @return $this
     */
    public function addOne(Server $server)
    {
        return $this->add([ $server ]);
    }

    /**
     * @param Server[] $servers
     * @return $this
     */
    public function add($servers)
    {
        $this->servers = array_merge($this->servers, $servers);
        usort($this->servers, function(Server $a, Server $b) {
            return strlen($b->getZone()) - strlen($a->getZone());
        });
        return $this;
    }

    /**
     * @param string $domain
     * @return Server[]
     */
    public function match($domain)
    {
        $servers = [];
        $maxlen = 0;
        foreach ($this->servers as $server) {
            $zone = $server->getZone();
            if (strlen($zone) < $maxlen) {
                break;
            }
            if ($server->isDomainZone($domain)) {
                $servers[] = $server;
                $maxlen = max($maxlen, strlen($zone));
            }
        }
        return $servers;
    }
}