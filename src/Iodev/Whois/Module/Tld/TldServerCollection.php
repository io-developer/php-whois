<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

class TldServerCollection
{
    /** @var TldServer[] */
    protected array $servers = [];

    /**
     * @return TldServer[]
     */
    public function getServers(): array
    {
        return $this->servers;
    }

    /**
     * @param TldServer[] $servers
     */
    public function addServers(array $servers): static
    {
        return $this->setServers(array_merge($this->servers, $servers));
    }

    /**
     * @param TldServer[] $servers
     */
    public function setServers(array $servers): static
    {
        $sortedKeys = [];
        $counter = 0;
        $serversCount = count($servers);
        foreach ($servers as $key => $server) {
            $counter++;
            $parts = explode('.', $server->zone);
            $len = count($parts);
            $rootZone = $parts[$len - 1] ?? '';
            $subZone1 = $parts[$len - 2] ?? '';
            $subZone2 = $parts[$len - 3] ?? '';
            $sortedKeys[$key] = sprintf(
                '%16s.%16s.%32s.%13s',
                $subZone2,
                $subZone1,
                $rootZone,
                $serversCount - $counter,
            );
        };

        uksort($sortedKeys, function($keyA, $keyB) use ($sortedKeys) {
            return strcmp($sortedKeys[$keyB], $sortedKeys[$keyA]);
        });

        $sortedServers = [];
        foreach ($sortedKeys as $key => $unused) {
            if (is_string($key)) {
                $sortedServers[$key] = $servers[$key];
            } else {
                $sortedServers[] = $servers[$key];
            }
        }

        $this->servers = $sortedServers;

        return $this;
    }
}
