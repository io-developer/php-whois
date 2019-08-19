<?php

namespace Iodev\Whois;

use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Modules\Asn\AsnModule;
use Iodev\Whois\Modules\Asn\AsnServer;
use Iodev\Whois\Modules\Tld\TldModule;
use Iodev\Whois\Modules\Tld\TldServer;

class WhoisFactory implements IWhoisFactory
{
    /**
     * @return Whois
     */
    public function createWhois(): Whois
    {
        $whois = new Whois($this->createLoader());
        $whois->setFactory($this);
        return $whois;
    }

    /**
     * @return ILoader
     */
    public function createLoader(): ILoader
    {
        return new SocketLoader();
    }

    /**
     * @param ILoader $loader
     * @param AsnServer[] $servers
     * @return AsnModule
     */
    public function createAsnModule(ILoader $loader = null, $servers = null): AsnModule
    {
        $m = new AsnModule($loader);
        $m->setServers($servers ?: AsnServer::fromDataList(Config::load("module.asn.servers")));
        return $m;
    }

    /**
     * @param ILoader $loader
     * @param TldServer[] $servers
     * @return TldModule
     */
    public function createTldModule(ILoader $loader = null, $servers = null): TldModule
    {
        $m = new TldModule($loader);
        $m->setServers($servers ?: TldServer::fromDataList(Config::load("module.tld.servers")));
        return $m;
    }
}
