<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Module;
use Iodev\Whois\Modules\ModuleType;

class TldModule extends Module
{
    /**
     * @param ILoader $loader
     */
    public function __construct(ILoader $loader)
    {
        parent::__construct(ModuleType::TLD, $loader);
    }

    /** @var TldServer[] */
    protected $servers = [];

    /** @var TldServer[] */
    protected $lastUsedServers = [];

    /**
     * @return TldServer[]
     */
    public function getServers()
    {
        return $this->servers;
    }

    /**
     * @return TldServer[]
     */
    public function getLastUsedServers()
    {
        return $this->lastUsedServers;
    }

    /**
     * @param TldServer[] $servers
     * @return $this
     */
    public function addServers($servers)
    {
        return $this->setServers(array_merge($this->servers, $servers));
    }

    /**
     * @param TldServer[] $servers
     * @return $this
     */
    public function setServers($servers)
    {
        $sortedKeys = [];
        $counter = 0;
        $serversCount = count($servers);
        foreach ($servers as $key => $server) {
            $counter++;
            $parts = explode('.', $server->getZone());
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
     * @param string $domain
     * @param bool $quiet
     * @return TldServer[]
     * @throws ServerMismatchException
     */
    public function matchServers($domain, $quiet = false)
    {
        $domainAscii = DomainHelper::toAscii($domain);
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
     * @param string $domain
     * @return bool
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function isDomainAvailable($domain)
    {
        return !$this->loadDomainInfo($domain);
    }

    /**
     * @param string $domain
     * @param TldServer $server
     * @return TldResponse
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain($domain, TldServer $server = null)
    {
        $servers = $server ? [$server] : $this->matchServers($domain);
        list ($response) = $this->loadDomainData($domain, $servers);
        return $response;
    }

    /**
     * @param string $domain
     * @param TldServer $server
     * @return TldInfo
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainInfo($domain, TldServer $server = null)
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
        $host = $host ?: $server->getHost();
        $query = $server->buildDomainQuery($domain, $strict);
        $text = $this->getLoader()->loadText($host, $query);
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
        $domain = DomainHelper::toAscii($domain);
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
     * @param $domain
     * @param $strict
     * @param $host
     * @param $lastError
     * @throws ConnectionException
     * @throws WhoisException
     */
    protected function loadParsedTo(&$outResponse, &$outInfo, $server, $domain, $strict = false, $host = null, &$lastError = null)
    {
        try {
            $outResponse = $this->loadResponse($server, $domain, $strict, $host);
            $outInfo = $server->getParser()->parseResponse($outResponse);
        } catch (ConnectionException $e) {
            $lastError = $lastError ?: $e;
        }
        if (!$outInfo && $lastError && $host == $server->getHost() && $strict) {
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
        if ($host && $host != $server->getHost() && !$server->isCentralized()) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, false, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
    }
}
