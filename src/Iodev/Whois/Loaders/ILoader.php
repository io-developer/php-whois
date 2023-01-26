<?php

declare(strict_types=1);

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\WhoisException;

interface ILoader
{
    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    function loadText(string $whoisHost, string $query): string;
}