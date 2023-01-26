<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\ServerMismatchException;
use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Loader\ILoader;
use Iodev\Whois\Tool\DomainTool;

class TldModule
{
    /** @var TldServer[] */
    protected array $servers = [];

    /** @var TldServer[] */
    protected array $lastUsedServers = [];


    public function __construct(
        protected ILoader $loader,
        protected DomainTool $domainTool,
    ) {}

    /**
     * @return TldServer[]
     */
    public function getServers(): array
    {
        return $this->servers;
    }

    /**
     * @return TldServer[]
     */
    public function getLastUsedServers(): array
    {
        return $this->lastUsedServers;
    }

    /**
     * @param TldServer[] $servers
     */
    public function addServers(array $servers): static
    {
        return $this->setServers(array_merge($this->servers, $servers));
    }

    /**
     * @param TldServer[] $servers
     */
    public function setServers(array $servers): static
    {
        $sortedKeys = [];
        $counter = 0;
        $serversCount = count($servers);
        foreach ($servers as $key => $server) {
            $counter++;
            $parts = explode('.', $server->zone);
            $len = count($parts);
            $rootZone = $parts[$len - 1] ?? '';
            $subZone1 = $parts[$len - 2] ?? '';
            $subZone2 = $parts[$len - 3] ?? '';
            $sortedKeys[$key] = sprintf(
                '%16s.%16s.%32s.%13s',
                $subZone2,
                $subZone1,
                $rootZone,
                $serversCount - $counter,
            );
        };

        uksort($sortedKeys, function($keyA, $keyB) use ($sortedKeys) {
            return strcmp($sortedKeys[$keyB], $sortedKeys[$keyA]);
        });

        $sortedServers = [];
        foreach ($sortedKeys as $key => $unused) {
            if (is_string($key)) {
                $sortedServers[$key] = $servers[$key];
            } else {
                $sortedServers[] = $servers[$key];
            }
        }

        $this->servers = $sortedServers;

        return $this;
    }

    /**
     * @return TldServer[]
     * @throws ServerMismatchException
     */
    public function matchServers(string $domain, bool $quiet = false): array
    {
        $domainAscii = $this->domainTool->toAscii($domain);
        $servers = [];
        foreach ($this->servers as $server) {
            $matchedCount = $server->matchDomainZone($domainAscii);
            if ($matchedCount) {
                $servers[] = $server;
            }
        }
        if (!$quiet && empty($servers)) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }
        return $servers;
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function isDomainAvailable(string $domain): bool
    {
        return !$this->loadDomainInfo($domain);
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain(string $domain, TldServer $server = null): TldResponse
    {
        $servers = $server ? [$server] : $this->matchServers($domain);
        list ($response) = $this->loadDomainData($domain, $servers);
        return $response;
    }

    /**
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainInfo(string $domain, TldServer $server = null): ?TldInfo
    {
        $servers = $server ? [$server] : $this->matchServers($domain);
        list (, $info) = $this->loadDomainData($domain, $servers);
        return $info;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadResponse(TldServer $server, string $domain, bool $strict = false, ?string $host = null): TldResponse
    {
        $host = $host ?: $server->host;
        $query = $server->buildDomainQuery($domain, $strict);
        $text = $this->loader->loadText($host, $query);
        return new TldResponse(
            $domain,
            $host,
            $query,
            $text,
        );
    }

    /**
     * @param TldServer[] $servers
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainData(string $domain, array $servers): array
    {
        $this->lastUsedServers = [];
        $domain = $this->domainTool->toAscii($domain);
        $response = null;
        $info = null;
        $lastError = null;
        foreach ($servers as $server) {
            $this->lastUsedServers[] = $server;
            $this->loadParsedTo($response, $info, $server, $domain, false, null, $lastError);
            if ($info) {
                break;
            }
        }
        if (!$response && !$info) {
            throw $lastError ? $lastError : new WhoisException("No response");
        }
        return [$response, $info];
    }

    /**
     * @param $outResponse
     * @param TldInfo $outInfo
     * @param TldServer $server
     * @throws ConnectionException
     * @throws WhoisException
     */
    protected function loadParsedTo(
        &$outResponse,
        &$outInfo,
        TldServer $server,
        string $domain,
        bool $strict = false,
        ?string $host = null,
        &$lastError = null,
    ) {
        try {
            $outResponse = $this->loadResponse($server, $domain, $strict, $host);
            $outInfo = $server->parser->parseResponse($outResponse);
        } catch (ConnectionException $e) {
            $lastError = $lastError ?: $e;
        }
        if (!$outInfo && $lastError && $host == $server->host && $strict) {
            throw $lastError;
        }
        if (!$strict && !$outInfo) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, true, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
        if (!$outInfo || $host == $outInfo->whoisServer) {
            return;
        }
        $host = $outInfo->whoisServer;
        if ($host && $host != $server->host && !$server->centralized) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, false, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
    }
}
