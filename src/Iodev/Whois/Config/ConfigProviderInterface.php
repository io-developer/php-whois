<?php

declare(strict_types=1);

namespace Iodev\Whois\Config;

interface ConfigProviderInterface
{
    public function get(string $id): mixed;
}
