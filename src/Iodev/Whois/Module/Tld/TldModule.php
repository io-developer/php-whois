<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\ServerMismatchException;
use Iodev\Whois\Exception\WhoisException;

class TldModule
{
    /** @var TldServer[] */
    protected array $servers = [];

    public function __construct(
        protected TldLoader $loader,
        protected TldServerCollection $serverCollection,
        protected TldServerMatcher $serverMatcher,
    ) {}

    public function getLoader(): TldLoader
    {
        return $this->loader;
    }

    public function getServerCollection(): TldServerCollection
    {
        return $this->serverCollection;
    }

    public function getServerMatcher(): TldServerMatcher
    {
        return $this->serverMatcher;
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain(string $domain, TldServer $server = null): TldResponse
    {
        $servers = $server !== null
            ? [$server]
            : $this->serverMatcher->match($this->serverCollection->getServers(), $domain)
        ;
        $this->loader->loadDomainData($domain, $servers);
        return $this->loader->getLoadedResponse();
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainInfo(string $domain, TldServer $server = null): ?TldInfo
    {
        $servers = $server !== null
            ? [$server]
            : $this->serverMatcher->match($this->serverCollection->getServers(), $domain)
        ;
        $this->loader->loadDomainData($domain, $servers);
        return $this->loader->getLoadedInfo();
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function isDomainBusy(string $domain): bool
    {
        return $this->loadDomainInfo($domain) !== null;
    }

    /**
     * @deprecated use isDomainBusy()
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function isDomainAvailable(string $domain): bool
    {
        return !$this->isDomainBusy($domain);
    }
}
