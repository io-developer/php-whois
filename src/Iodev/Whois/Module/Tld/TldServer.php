<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

class TldServer
{ 
    public const DEFAULT_QUERY_FORMAT = "%s\r\n";

    /** @var string[] */
    protected $inverseZoneParts;

    public function __construct(
        public readonly string $zone,
        public readonly string $host,
        public readonly bool $centralized,
        public readonly TldParser $parser,
        public readonly string $queryFormat,
    ) {
        $this->inverseZoneParts = array_reverse(explode('.', $this->zone));
        array_pop($this->inverseZoneParts);
    }

    public function isDomainZone(string $domain): bool
    {
        return $this->matchDomainZone($domain) > 0;
    }

    public function matchDomainZone(string $domain): int
    {
        $domainParts = explode('.', $domain);
        if ($this->zone === '.' && count($domainParts) === 1) {
            return 1;
        }
        array_shift($domainParts);
        $domainCount = count($domainParts);
        $zoneCount = count($this->inverseZoneParts);
        if (count($domainParts) < $zoneCount) {
            return 0;
        }
        $i = -1;
        while (++$i < $zoneCount) {
            $zonePart = $this->inverseZoneParts[$i];
            $domainPart = $domainParts[$domainCount - $i - 1];
            if ($zonePart != $domainPart && $zonePart != '*') {
                return 0;
            }
        }
        return $zoneCount;
    }

    public function buildDomainQuery(string $domain, bool $strict = false): string
    {
        $query = sprintf($this->queryFormat, $domain);
        return $strict ? "=$query" : $query;
    }
}
