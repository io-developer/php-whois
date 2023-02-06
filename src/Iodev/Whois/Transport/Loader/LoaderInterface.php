<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Loader;

use Iodev\Whois\Error\ConnectionException;
use Iodev\Whois\Error\WhoisException;

interface LoaderInterface
{
    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    function loadText(string $whoisHost, string $query): string;
}