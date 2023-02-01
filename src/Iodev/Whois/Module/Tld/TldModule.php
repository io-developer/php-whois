<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\ServerMismatchException;
use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Module\Tld\Command\LookupCommand;
use Iodev\Whois\Module\Tld\Dto\LookupInfo;
use Iodev\Whois\Module\Tld\Dto\LookupResponse;
use Iodev\Whois\Module\Tld\Dto\LookupResult;
use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Module\Tld\Parsing\ParserInterface;
use Iodev\Whois\Module\Tld\Whois\ServerProviderInterface;
use Iodev\Whois\Transport\Loader\LoaderInterface;
use Psr\Container\ContainerInterface;

class TldModule
{
    public const LOOKUP_DOMAIN_RECURSION_MAX = 1;

    /** @var WhoisServer[] */
    protected array $lastUsedServers = [];

    public function __construct(
        protected ContainerInterface $container,
        protected LoaderInterface $loader,
        protected ServerProviderInterface $serverProvider,
    ) {}

    public function getLoader(): LoaderInterface
    {
        return $this->loader;
    }

    public function getServerProvider(): ServerProviderInterface
    {
        return $this->serverProvider;
    }

    /**
     * @return WhoisServer[]
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
    public function loadDomainResponse(string $domain, WhoisServer $server = null): LookupResponse
    {
        $result = $this->lookupDomain($domain, null, $server);
        return $result->response;
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainInfo(string $domain, WhoisServer $server = null): ?LookupInfo
    {
        $result = $this->lookupDomain($domain, null, $server);
        return $result->info;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain(
        string $domain,
        ?string $overrideHost = null,
        ?WhoisServer $overrideServer = null,
        ?ParserInterface $overrideParser = null,
    ): LookupResult {
        $this->lastUsedServers = [];

        /** @var WhoisServer[] */
        $servers = $overrideServer !== null
            ? [$overrideServer]
            : $this->serverProvider->getMatched($domain)
        ;
        if (count($servers) == 0) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }

        foreach ($servers as $server) {
            $this->lastUsedServers[] = $server;

            /** @var LookupCommand */
            $command = $this->container->get(LookupCommand::class);
            $command
                ->setLoader($this->loader)
                ->setDomain($domain)
                ->setHost($overrideHost ?: $server->getHost())
                ->setQueryFormat($server->getQueryFormat())
                ->setRecursionLimit($server->getCentralized() ? 0 : static::LOOKUP_DOMAIN_RECURSION_MAX)
                ->setParser($overrideParser ?: $server->getParser())
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
}
