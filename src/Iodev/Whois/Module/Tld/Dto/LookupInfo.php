<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Dto;

/**
 * @property string[] $nameServers
 * @property string[] $states
 */
class LookupInfo
{
    public function __construct(
        public readonly LookupResponse $response,
        public readonly string $parserType = '',
        public readonly string $domainName = '',
        public readonly string $domainNameUnicode = '',
        public readonly string $whoisServer = '',
        public readonly array $nameServers = [],
        public readonly int $creationDate = 0,
        public readonly int $expirationDate = 0,
        public readonly int $updatedDate = 0,
        public readonly array $states = [],
        public readonly string $owner = '',
        public readonly string $registrar = '',
        public readonly string $dnssec = '',
        public readonly array $extra = [],
    ) {}
}
