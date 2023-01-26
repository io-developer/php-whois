<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

class TldResponse
{
    public function __construct(
        public readonly string $domain = '',
        public readonly string $host = '',
        public readonly string $query = '',
        public readonly string $text = '',
    ) {}
}
