<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

interface AsnServerProviderInterface
{
    /**
     * @return ASnServer[]
     */
    public function getList(): array;

    public function create(array $config): ASnServer;

    /**
     * @return ASnServer[]
     */
    public function createMany(array $configList): array;
}
