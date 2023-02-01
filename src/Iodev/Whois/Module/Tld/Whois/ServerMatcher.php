<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Whois;

use Iodev\Whois\Exception\ServerMismatchException;
use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Tool\DomainTool;

class ServerMatcher
{
    public function __construct(
        protected DomainTool $domainTool,
    ) {}
    
    /**
     * @param WhoisServer[] $servers
     * @return WhoisServer[]
     * @throws ServerMismatchException
     */
    public function match(array $servers, string $domain): array
    {
        $domainAscii = $this->domainTool->toAscii($domain);
        $matchedServers = [];
        foreach ($servers as $server) {
            $matchedCount = $this->matchDomainZone($server, $domainAscii);
            if ($matchedCount) {
                $matchedServers[] = $server;
            }
        }
        return $matchedServers;
    }

    public function isDomainZone(WhoisServer $server, string $domain): bool
    {
        return $this->matchDomainZone($server, $domain) > 0;
    }

    public function matchDomainZone(WhoisServer $server, string $domain): int
    {
        $domainParts = explode('.', $domain);
        if ($server->zone === '.' && count($domainParts) === 1) {
            return 1;
        }
        array_shift($domainParts);
        $domainCount = count($domainParts);
        $invZoneParts = $server->getInverseZoneParts();
        $zoneCount = count($invZoneParts);
        if (count($domainParts) < $zoneCount) {
            return 0;
        }
        $i = -1;
        while (++$i < $zoneCount) {
            $zonePart = $invZoneParts[$i];
            $domainPart = $domainParts[$domainCount - $i - 1];
            if ($zonePart != $domainPart && $zonePart != '*') {
                return 0;
            }
        }
        return $zoneCount;
    }
}
