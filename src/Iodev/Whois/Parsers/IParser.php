<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\DomainInfo;
use Iodev\Whois\Response;

interface IParser
{
    /**
     * @param Response $response
     * @return DomainInfo
     */
    function parseResponse(Response $response);
}
