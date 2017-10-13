<?php

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Response;

interface ILoader
{
    /**
     * @param string $whoisHost
     * @param string $domain
     * @param bool $strict
     * @return Response
     * @throws ConnectionException
     */
    function loadResponse($whoisHost, $domain, $strict = false);
}