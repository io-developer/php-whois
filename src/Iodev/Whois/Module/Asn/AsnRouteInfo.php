<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Asn;

class AsnRouteInfo
{
    public function __construct(
        public readonly string $route = '',
        public readonly string $route6 = "",
        public readonly string $descr = "",
        public readonly string $origin = "",
        public readonly string $mntBy = "",
        public readonly string $changed = "",
        public readonly string $source = "",
    ) {}
}
