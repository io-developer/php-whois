<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

class AsnResponse
{
    public function __construct(
        public readonly string $asn,
        public readonly string $host,
        public readonly string $query,
        public readonly string $text,
    ) {}
}
