<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewDto;

use \Iodev\Whois\Module\Tld\Dto\WhoisServer;

class SingleLookupRequest
{
    protected string $domain = '';
    protected ?WhoisServer $whoisServer = null;
    protected int $transportTimeout = 0;
    protected bool $useAltQuery = false;
    protected int $recursionDepth = 0;

    public function setDomain(string $domain): static
    {
        $this->domain = $domain;
        return $this;
    }

    public function getDomain(): string
    {
        return $this->domain;
    }

    public function setWhoisServer(WhoisServer $server): static
    {
        $this->whoisServer = $server;
        return $this;
    }

    public function getWhoisServer(): ?WhoisServer
    {
        return $this->whoisServer;
    }

    public function setTransportTimeout(int $seconds): static
    {
        $this->transportTimeout = $seconds;
        return $this;
    }

    public function getTransportTimeout(): int
    {
        return $this->transportTimeout;
    }

    public function setUseAltQuery(bool $yes): static
    {
        $this->useAltQuery = $yes;
        return $this;
    }

    public function getUseAltQuery(): bool
    {
        return $this->useAltQuery;
    }

    public function setRecursionDepth(int $depth): static
    {
        $this->recursionDepth = $depth;
        return $this;
    }

    public function getRecursionDepth(): int
    {
        return $this->recursionDepth;
    }
}
