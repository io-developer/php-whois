<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Dto;

class LookupResponse
{
    public function __construct(
        public readonly string $domain = '',
        public readonly string $host = '',
        public readonly string $query = '',
        public readonly string $text = '',
    ) {}
}
