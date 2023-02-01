<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Dto;
use Iodev\Whois\Module\Tld\Parsing\ParserInterface;

class WhoisServer
{ 
    /** @var string[] */
    protected $inverseZoneParts;

    public function __construct(
        public readonly string $zone,
        public readonly string $host,
        public readonly bool $centralized,
        public readonly ParserInterface $parser,
        public readonly string $queryFormat,
        public readonly int $priority,
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
