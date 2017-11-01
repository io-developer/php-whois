<?php

namespace Iodev\Whois\ServerProviders;

use Iodev\Whois\Server;

interface IServerProvider
{
    /**
     * @param string $domain
     * @return Server[]
     */
    function getServersForDomain($domain);
}
