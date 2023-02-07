<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewDto;

use \Iodev\Whois\Module\Tld\Dto\WhoisServer;

class IntermediateLookupRequest
{
    protected ?string $domain = null;
    protected ?WhoisServer $whoisServer = null;
    protected bool $_isAlt = false;
    protected int $recursionDepth = 0;

    public function setDomain(string $domain): static
    {
        $this->domain = $domain;
        return $this;
    }

    public function getDomain(): ?string
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

    public function setIsAlt(bool $alt): static
    {
        $this->_isAlt = $alt;
        return $this;
    }

    public function isAlt(): bool
    {
        return $this->_isAlt;
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
