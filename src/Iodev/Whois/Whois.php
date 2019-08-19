<?php

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Asn\AsnInfo;
use Iodev\Whois\Modules\Asn\AsnModule;
use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Modules\Tld\DomainResponse;
use Iodev\Whois\Modules\Tld\TldModule;

class Whois
{
    /**
     * @return Whois
     */
    public static function create()
    {
        return WhoisFactory::getInstance()->createWhois();
    }

    /**
     * @param ILoader $loader
     */
    public function __construct(ILoader $loader)
    {
        $this->loader = $loader;
    }

    /** @var IWhoisFactory */
    private $factory;

    /** @var ILoader */
    private $loader;

    /** @var TldModule */
    private $tldModule;

    /** @var AsnModule */
    private $asnModule;

    /**
     * @param IWhoisFactory $factory
     * @return $this
     */
    public function setFactory(IWhoisFactory $factory)
    {
        $this->factory = $factory;
        return $this;
    }

    /**
     * @return IWhoisFactory
     */
    public function getFactory(): IWhoisFactory
    {
        return $this->factory ?: WhoisFactory::getInstance();
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
        $this->tldModule = $this->tldModule ?: $this->getFactory()->createTldModule($this->loader);
        return $this->tldModule;
    }

    /**
     * @return AsnModule
     */
    public function getAsnModule()
    {
        $this->asnModule = $this->asnModule ?: $this->getFactory()->createAsnModule($this->loader);
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
     * @return DomainResponse
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
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
     * @throws WhoisException
     */
    public function loadDomainInfo($domain)
    {
        return $this->getTldModule()->loadDomainInfo($domain);
    }

    /**
     * @param string $asn
     * @return Response
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupAsn($asn)
    {
        return $this->getAsnModule()->lookupAsn($asn);
    }

    /**
     * @param string $asn
     * @return AsnInfo
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadAsnInfo($asn)
    {
        return $this->getAsnModule()->loadAsnInfo($asn);
    }
}
