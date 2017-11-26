<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\Helpers\GroupHelper;
use Iodev\Whois\Response;

class FlatCommonParser extends CommonParser
{
    /**
     * @param Response $response
     * @return array
     */
    public function groupFrom(Response $response)
    {
        return GroupHelper::groupFromText($response->getText());
    }
}
