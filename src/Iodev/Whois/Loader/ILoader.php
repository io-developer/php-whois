<?php

declare(strict_types=1);

namespace Iodev\Whois\Loader;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\WhoisException;

interface ILoader
{
    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    function loadText(string $whoisHost, string $query): string;
}