<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Whois;

use Iodev\Whois\Module\Tld\Dto\WhoisServer;

class ServerCollection
{
    /** @var WhoisServer[] */
    protected array $servers = [];

    protected bool $isSorted = true;

    /**
     * @return WhoisServer[]
     */
    public function getList(): array
    {
        if (!$this->isSorted) {
            $this->sort();
        }
        return $this->servers;
    }

    public function add(WhoisServer $server): static
    {
        $this->isSorted = false;
        $this->servers[] = $server;
        return $this;
    }

    /**
     * @param WhoisServer[] $servers
     */
    public function addList(array $servers): static
    {
        foreach ($servers as $server) {
            $this->add($server);
        }
        return $this;
    }

    /**
     * @param WhoisServer[] $servers
     */
    public function setList(array $servers): static
    {
        $this->servers = [];
        $this->addList($servers);
        return $this;
    }

    public function sort(): static
    {
        $sortedKeys = [];
        $priorityMin = 0;
        foreach ($this->servers as $server) {
            $priorityMin = min($priorityMin, $server->priority);
        }
        $counter = 0;
        $serversCount = count($this->servers);
        foreach ($this->servers as $key => $server) {
            $counter++;
            $priority = $priorityMin + $server->priority;
            $subPriority = $serversCount - $counter;
            $parts = explode('.', $server->zone);
            $len = count($parts);
            $rootZone = $parts[$len - 1] ?? '';
            $subZone1 = $parts[$len - 2] ?? '';
            $subZone2 = $parts[$len - 3] ?? '';
            $sortedKeys[$key] = sprintf(
                '%16s.%16s.%32s.%8s.%8s',
                $subZone2,
                $subZone1,
                $rootZone,
                $priority,
                $subPriority,
            );
        };

        uksort($sortedKeys, function($keyA, $keyB) use ($sortedKeys) {
            return strcmp($sortedKeys[$keyB], $sortedKeys[$keyA]);
        });

        $sortedServers = [];
        foreach ($sortedKeys as $key => $unused) {
            if (is_string($key)) {
                $sortedServers[$key] = $this->servers[$key];
            } else {
                $sortedServers[] = $this->servers[$key];
            }
        }

        $this->servers = $sortedServers;
        $this->isSorted = true;

        return $this;
    }
}
