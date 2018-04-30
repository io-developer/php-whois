<?php

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Modules\Tld\TldModule;

class Whois
{
    /**
     * @param ILoader $loader
     * @return Whois
     */
    public static function create(ILoader $loader = null)
    {
        return new Whois($loader ?: new SocketLoader());
    }

    /**
     * @param ILoader $loader
     */
    public function __construct(ILoader $loader)
    {
        $this->loader = $loader;
    }

    /** @var ILoader */
    private $loader;

    /** @var TldModule */
    private $tldModule;

    /**
     * @return ILoader
     */
    public function getLoader()
    {
        return $this->loader;
    }

    /**
     * @return TldModule
     */
    public function getTldModule()
    {
        $this->tldModule = $this->tldModule ?: TldModule::create($this->loader);
        return $this->tldModule;
    }

    /**
     * @param string $domain
     * @return bool
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    public function isDomainAvailable($domain)
    {
        return $this->getTldModule()->isDomainAvailable($domain);
    }

    /**
     * @param string $domain
     * @return Response
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    public function lookupDomain($domain)
    {
        return $this->getTldModule()->lookupDomain($domain);
    }

    /**
     * @param string $domain
     * @return DomainInfo
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    public function loadDomainInfo($domain)
    {
        return $this->getTldModule()->loadDomainInfo($domain);
    }
}
