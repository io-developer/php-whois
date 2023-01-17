<?php

declare(strict_types=1);

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Asn\AsnInfo;
use Iodev\Whois\Modules\Asn\AsnModule;
use Iodev\Whois\Modules\Asn\AsnResponse;
use Iodev\Whois\Modules\Tld\TldInfo;
use Iodev\Whois\Modules\Tld\TldResponse;
use Iodev\Whois\Modules\Tld\TldModule;

class Whois
{
    /**
     * @param ILoader $loader
     */
    public function __construct(ILoader $loader)
    {
        $this->loader = $loader;
    }

    /** @var IFactory */
    private $factory;

    /** @var ILoader */
    private $loader;

    /** @var TldModule */
    private $tldModule;

    /** @var AsnModule */
    private $asnModule;

    /**
     * @param IFactory $factory
     * @return $this
     */
    public function setFactory(IFactory $factory)
    {
        $this->factory = $factory;
        return $this;
    }

    /**
     * @return IFactory
     */
    public function getFactory(): IFactory
    {
        return $this->factory ?: Factory::get();
    }

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
        $this->tldModule = $this->tldModule ?: $this->getFactory()->createTldModule($this);
        return $this->tldModule;
    }

    /**
     * @return AsnModule
     */
    public function getAsnModule()
    {
        $this->asnModule = $this->asnModule ?: $this->getFactory()->createAsnModule($this);
        return $this->asnModule;
    }

    /**
     * @param string $domain
     * @return bool
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function isDomainAvailable($domain)
    {
        return $this->getTldModule()->isDomainAvailable($domain);
    }

    /**
     * @param string $domain
     * @return TldResponse
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain($domain): TldResponse
    {
        return $this->getTldModule()->lookupDomain($domain);
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainInfo(string $domain): ?TldInfo
    {
        return $this->getTldModule()->loadDomainInfo($domain);
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupAsn(string $asn): AsnResponse
    {
        return $this->getAsnModule()->lookupAsn($asn);
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadAsnInfo(string $asn): ?AsnInfo
    {
        return $this->getAsnModule()->loadAsnInfo($asn);
    }
}
