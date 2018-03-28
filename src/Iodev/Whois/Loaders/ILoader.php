<?php

namespace Iodev\Whois\Loaders;

use Iodev\Whois\AsnResponse;
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

    /**
     * @param string $whoisHost
     * @param string $asn
     * @return AsnResponse
     * @throws ConnectionException
     */
    function loadAsnResponse($whoisHost, $asn);
}
