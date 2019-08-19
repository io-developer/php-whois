<?php

namespace Iodev\Whois;

use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Asn\AsnModule;
use Iodev\Whois\Modules\Asn\AsnServer;
use Iodev\Whois\Modules\Tld\TldModule;
use Iodev\Whois\Modules\Tld\TldParser;
use Iodev\Whois\Modules\Tld\TldServer;

interface IWhoisFactory
{
    /**
     * @param ILoader|null $loader
     * @return Whois
     */
    function createWhois(ILoader $loader = null): Whois;

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

    /**
     * @param array|null $configs
     * @param TldParser|null $defaultParser
     * @return TldServer[]
     */
    public function createTldSevers($configs = null, TldParser $defaultParser = null): array;

    /**
     * @param array $config
     * @param TldParser|null $defaultParser
     * @return TldServer
     */
    public function createTldSever(array $config, TldParser $defaultParser = null): TldServer;

    /**
     * @param array $config
     * @param TldParser|null $defaultParser
     * @return TldParser
     */
    public function createTldSeverParser(array $config, TldParser $defaultParser = null): TldParser;
}
