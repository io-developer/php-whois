<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

class TldLookupDomainResult
{    public function __construct(
        public readonly ?TldResponse $response,
        public readonly ?TldInfo $info,
    ) {}

    public function isDomainBusy(): bool
    {
        return $this->info !== null;
    }
}
