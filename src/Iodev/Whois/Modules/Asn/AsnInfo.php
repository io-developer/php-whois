<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

class AsnInfo
{
    /**
     * @param AsnRouteInfo[] $routes
     */
    public function __construct(
        public readonly AsnResponse $response,
        public readonly string $asn = '',
        public readonly array $routes = [],
    ) {}
}
