<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

class AsnInfo
{
    public function __construct(
        public readonly AsnResponse $response,
        public readonly string $asn = '',
        
        /** @var AsnRouteInfo[] */
        public readonly array $routes = [],
    ) {}
}
