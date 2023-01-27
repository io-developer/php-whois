<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Loader\LoaderInterface;
use Iodev\Whois\Tool\DomainTool;

class TldLoader
{
    protected mixed $lastError = null;

    /** @var TldServer[] */
    protected array $lastUsedServers = [];

    protected ?TldResponse $loadedResponse = null;
    protected ?TldInfo $loadedInfo = null;
    
    public function __construct(
        protected LoaderInterface $loader,
        protected DomainTool $domainTool,
    ) {}

    public function getLastError(): mixed
    {
        return $this->lastError;
    }

    /**
     * @return TldServer[]
     */
    public function getLastUsedServers(): array
    {
        return $this->lastUsedServers;
    }

    public function getLoadedResponse(): ?TldResponse
    {
        return $this->loadedResponse;
    }
    public function getLoadedInfo(): ?TldInfo
    {
        return $this->loadedInfo;
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
    public function loadDomainData(string $domain, array $servers): void
    {
        $this->lastError = null;
        $this->lastUsedServers = [];
        $this->loadedResponse = null;
        $this->loadedInfo = null;

        $domain = $this->domainTool->toAscii($domain);
        foreach ($servers as $server) {
            $this->lastUsedServers[] = $server;
            $this->loadParsedTo($server, $domain, false, null);
            if ($this->loadedInfo) {
                break;
            }
        }
        if (!$this->loadedResponse && !$this->loadedInfo) {
            throw $this->lastError ? $this->lastError : new WhoisException('No response');
        }
    }

    /**
     * @param $outResponse
     * @param TldInfo $outInfo
     * @param TldServer $server
     * @throws ConnectionException
     * @throws WhoisException
     */
    protected function loadParsedTo(
        TldServer $server,
        string $domain,
        bool $strict = false,
        ?string $host = null,
    ) {
        try {
            $this->loadedResponse = $this->loadResponse($server, $domain, $strict, $host);
        } catch (ConnectionException $err) {
            if ($this->lastError === null) {
                $this->lastError = $err;
            }
        }

        $this->loadedInfo = $server->parser->parseResponse($this->loadedResponse);

        if (
            $this->loadedInfo === null
            && $this->lastError !== null
            && $host == $server->host
            && $strict
        ) {
            throw $this->lastError;
        }

        if ($this->loadedInfo === null && !$strict) {
            $prevResponse = $this->loadedResponse;
            $prevInfo = $this->loadedInfo;
            
            $this->loadParsedTo($server, $domain, true, $host);
            
            if ($this->loadedInfo === null) {
                $this->loadedResponse = $prevResponse;
                $this->loadedInfo = $prevInfo;
            }
        }

        if ($this->loadedInfo === null || $host == $this->loadedInfo->whoisServer) {
            return;
        }

        $host = $this->loadedInfo->whoisServer;
        if ($host && $host != $server->host && !$server->centralized) {
            $prevResponse = $this->loadedResponse;
            $prevInfo = $this->loadedInfo;

            $this->loadParsedTo($server, $domain, false, $host);

            if ($this->loadedInfo === null) {
                $this->loadedResponse = $prevResponse;
                $this->loadedInfo = $prevInfo;
            }
        }
    }
}
