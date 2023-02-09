<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewDto;

use \Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Traits\TagContainerTrait;

class LookupRequest
{
    use TagContainerTrait;

    protected ?string $domain = null;
    protected ?string $customHost = null;
    protected ?string $customParserType = null;
    protected bool $altQueryingEnabled = true;
    protected bool $queryRecursionLimit = 1;

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

    public function setCustomHost(string $host): static
    {
        $this->customHost = $host;
        return $this;
    }

    public function getCustomHost(): ?string
    {
        return $this->customHost;
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
