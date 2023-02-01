<?php

declare(strict_types=1);

namespace Iodev\Whois;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\ServerMismatchException;
use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Module\Asn\AsnInfo;
use Iodev\Whois\Module\Asn\AsnModule;
use Iodev\Whois\Module\Asn\AsnResponse;
use Iodev\Whois\Module\Tld\Dto\LookupResult;
use Iodev\Whois\Module\Tld\TldModule;
use Psr\Container\ContainerInterface;

class Whois
{
    public function __construct(
        public readonly ContainerInterface $container,
        public readonly TldModule $tldModule,
        public readonly AsnModule $asnModule,
    ) {}


    public function setContainer(ContainerInterface $container): static
    {
        $this->container = $container;
        return $this;
    }

    public function getContainer(): ContainerInterface
    {
        return $this->container;
    }


    public function getTldModule(): TldModule
    {
        return $this->tldModule;
    }

    public function getAsnModule(): AsnModule
    {
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
        return !$this->getTldModule()->lookupDomain($domain)->isDomainBusy();
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain(string $domain): LookupResult
    {
        return $this->getTldModule()->lookupDomain($domain);
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
