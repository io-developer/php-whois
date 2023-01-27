<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

interface TldServerProviderInterface
{
    public function getCollection(): TldServerCollection;

    public function fromConfig(array $config): TldServer;
}
