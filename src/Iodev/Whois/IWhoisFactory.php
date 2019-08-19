<?php

namespace Iodev\Whois;

use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Asn\AsnModule;
use Iodev\Whois\Modules\Asn\AsnServer;
use Iodev\Whois\Modules\Tld\TldModule;
use Iodev\Whois\Modules\Tld\TldServer;

interface IWhoisFactory
{
    /**
     * @return Whois
     */
    function createWhois(): Whois;

    /**
     * @return ILoader
     */
    function createLoader(): ILoader;

    /**
     * @param ILoader $loader
     * @param AsnServer[] $servers
     * @return AsnModule
     */
    function createAsnModule(ILoader $loader = null, $servers = null): AsnModule;

    /**
     * @param ILoader $loader
     * @param TldServer[] $servers
     * @return TldModule
     */
    function createTldModule(ILoader $loader = null, $servers = null): TldModule;
}
