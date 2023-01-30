<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

class TldLookupDomainResult
{    public function __construct(
        public readonly ?TldResponse $response,
        public readonly ?TldInfo $info,
    ) {}
}
