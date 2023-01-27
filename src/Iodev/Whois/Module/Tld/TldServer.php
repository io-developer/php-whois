<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

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

    public function getInverseZoneParts(): array
    {
        return $this->inverseZoneParts;
    }

    public function buildDomainQuery(string $domain, bool $strict = false): string
    {
        $query = sprintf($this->queryFormat, $domain);
        return $strict ? "=$query" : $query;
    }
}
