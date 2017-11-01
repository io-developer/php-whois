<?php

namespace Iodev\Whois\ServerProviders;

use Iodev\Whois\Server;

class CommonServerProvider implements IServerProvider
{
    /**
     *  @param Server[] $servers
     */
    public function __construct($servers)
    {
        $this->addServers($servers);
    }

    /** @var Server[] */
    private $servers = [];

    /**
     * @param Server $server
     * @return $this
     */
    public function addServer(Server $server)
    {
        return $this->addServers([ $server ]);
    }

    /**
     * @param Server[] $servers
     * @return $this
     */
    public function addServers($servers)
    {
        $this->servers = array_merge($this->servers, $servers);
        usort($this->servers, function(Server $a, Server $b) {
            return strcmp($b->getZone(), $a->getZone());
        });
        return $this;
    }

    /**
     * @param string $domain
     * @return Server[]
     */
    public function getServersForDomain($domain)
    {
        $servers = [];
        $maxlen = 0;
        foreach ($this->servers as $server) {
            $zone = $server->getZone();
            if (strlen($zone) < $maxlen) {
                break;
            }
            if (DomainHelper::belongsToZone($domain, $zone)) {
                $servers[] = $server;
                $maxlen = max($maxlen, strlen($zone));
            }
        }
        return $servers;
    }
}
