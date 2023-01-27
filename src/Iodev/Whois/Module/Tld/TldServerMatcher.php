<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Exception\ServerMismatchException;
use Iodev\Whois\Tool\DomainTool;

class TldServerMatcher
{
    public function __construct(
        protected DomainTool $domainTool,
    ) {}
    
    /**
     * @param TldServer[] $servers
     * @return TldServer[]
     * @throws ServerMismatchException
     */
    public function match(array $servers, string $domain, bool $quiet = false): array
    {
        $domainAscii = $this->domainTool->toAscii($domain);
        $matchedServers = [];
        foreach ($servers as $server) {
            $matchedCount = $this->matchDomainZone($server, $domainAscii);
            if ($matchedCount) {
                $matchedServers[] = $server;
            }
        }
        if (count($matchedServers) == 0 && !$quiet) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }
        return $matchedServers;
    }

    public function isDomainZone(TldServer $server, string $domain): bool
    {
        return $this->matchDomainZone($server, $domain) > 0;
    }

    public function matchDomainZone(TldServer $server, string $domain): int
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
