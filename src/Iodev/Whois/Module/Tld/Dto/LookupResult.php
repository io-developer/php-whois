<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Dto;

class LookupResult
{    public function __construct(
        public readonly ?LookupResponse $response,
        public readonly ?LookupInfo $info,
    ) {}

    public function isDomainBusy(): bool
    {
        return $this->info !== null;
    }
}
