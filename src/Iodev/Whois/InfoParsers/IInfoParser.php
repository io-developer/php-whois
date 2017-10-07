<?php

namespace Iodev\Whois\InfoParsers;

use Iodev\Whois\Info;
use Iodev\Whois\Response;

interface IInfoParser
{
    /**
     * @param Response $response
     * @return Info
     */
    function fromResponse(Response $response);
}
