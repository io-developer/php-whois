<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

class TldServer
{ 
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

    /**
     * @param string $domain
     * @return bool
     */
    public function isDomainZone($domain)
    {
        return $this->matchDomainZone($domain) > 0;
    }

    /**
     * @param string $domain
     * @return int
     */
    public function matchDomainZone($domain)
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

    /**
     * @param string $domain
     * @param bool $strict
     * @return string
     */
    public function buildDomainQuery($domain, $strict = false)
    {
        $query = sprintf($this->queryFormat, $domain);
        return $strict ? "=$query" : $query;
    }
}
