<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

interface TldServerProviderInterface
{
    /**
     * @return TldServer[]
     */
    public function getList(): array;

    public function getCollection(): TldServerCollection;

    public function create(array $config): TldServer;

    /**
     * @return TldServer[]
     */
    public function createMany(array $configList): array;
}
