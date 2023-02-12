<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewDto;

use \Iodev\Whois\Module\Tld\Dto\WhoisServer;

class LookupRequestData
{
    protected ?string $domain = null;
    protected ?string $customWhoisHost = null;
    protected ?string $customParserType = null;
    protected bool $altQueryingEnabled = true;
    protected bool $queryRecursionLimit = 1;
    protected int $transportTimeout = 0;

    /** @var WhoisServer[] */
    protected array $whoisServers = [];

    public function setDomain(string $domain): static
    {
        $this->domain = $domain;
        return $this;
    }

    public function getDomain(): ?string
    {
        return $this->domain;
    }

    public function setCustomWhoisHost(string $host): static
    {
        $this->customWhoisHost = $host;
        return $this;
    }

    public function getCustomWhoisHost(): ?string
    {
        return $this->customWhoisHost;
    }

    public function setCustomParserType(string $type): static
    {
        $this->customParserType = $type;
        return $this;
    }

    public function getCustomParserType(): ?string
    {
        return $this->customParserType;
    }

    public function setAltQueryingEnabled(bool $enabled): static
    {
        $this->altQueryingEnabled = $enabled;
        return $this;
    }

    public function getAltQueryingEnabled(): bool
    {
        return $this->altQueryingEnabled;
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

    /**
     * @param WhoisServer[] $servers
     */
    public function setWhoisServers(array $servers): static
    {
        $this->whoisServers = [];
        foreach ($servers as $server) {
            $this->addWhoisServer($server);
        }
        return $this;
    }

    public function addWhoisServer(WhoisServer $server): static
    {
        $this->whoisServers[] = $server;
        return $this;
    }

    /**
     * @return WhoisServer[]
     */
    public function getWhoisServers(): array
    {
        return $this->whoisServers;
    }
}
