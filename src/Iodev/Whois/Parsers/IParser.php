<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\Info;
use Iodev\Whois\Response;

interface IParser
{
    /**
     * @param Response $response
     * @return Info
     */
    function parseResponse(Response $response);
}
