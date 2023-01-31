<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

class TldLookupWhoisResult
{    public function __construct(
        public readonly ?TldResponse $response,
        public readonly ?TldInfo $info,
    ) {}
}
