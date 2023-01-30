<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\ServerMismatchException;
use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Loader\LoaderInterface;
use Psr\Container\ContainerInterface;

class TldModule
{
    public const LOOKUP_DOMAIN_RECURSION_MAX = 1;

    /** @var TldServer[] */
    protected array $lastUsedServers = [];

    public function __construct(
        protected ContainerInterface $container,
        protected LoaderInterface $loader,
        protected TldServerProviderInterface $serverProvider,
    ) {}

    public function getLoader(): LoaderInterface
    {
        return $this->loader;
    }

    public function getServerProvider(): TldServerProviderInterface
    {
        return $this->serverProvider;
    }

    /**
     * @return TldServer[]
     */
    public function getLastUsedServers(): array
    {
        return $this->lastUsedServers;
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain(string $domain, TldServer $server = null): TldResponse
    {
        $result = $this->lookupDomainCmd($domain, $server);
        return $result->response;
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainInfo(string $domain, TldServer $server = null): ?TldInfo
    {
        $result = $this->lookupDomainCmd($domain, $server);
        return $result->info;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomainCmd(string $domain, TldServer $server = null): TldLookupDomainResult
    {
        $this->lastUsedServers = [];

        $servers = $server !== null
            ? [$server]
            : $this->serverProvider->getMatched($domain)
        ;
        if (count($servers) == 0) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }

        foreach ($servers as $server) {
            $this->lastUsedServers[] = $server;

            /** @var TldLookupDomainCommand */
            $command = $this->container->get(TldLookupDomainCommand::class);
            $command
                ->setLoader($this->loader)
                ->setDomain($domain)
                ->setHost($server->host)
                ->setQueryFormat($server->queryFormat)
                ->setRecursionLimit($server->centralized ? 0 : static::LOOKUP_DOMAIN_RECURSION_MAX)
                ->setParser($server->parser)
                ->execute()
            ;
            if ($command->getResult() !== null && $command->getResult()->info) {
                break;
            }
        }

        $result = $command->getResult();

        if ($result->response === null && $result->info === null) {
            throw new WhoisException('No response');
        }

        return $result;
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
