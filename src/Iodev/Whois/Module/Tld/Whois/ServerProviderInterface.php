<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Whois;

interface ServerProviderInterface
{
    public function getCollection(): ServerCollection;

    public function getMatched(string $domain): array;
}
