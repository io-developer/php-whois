<?php

declare(strict_types=1);

namespace Iodev\Whois\Routing;

use Iodev\Whois\Traits\TagContainerTrait;

class LookupRequest
{
    use TagContainerTrait;

    protected ?string $subject = null;
    protected ?string $whoisHost = null;
    protected ?string $moduleType = null;

    public function setSubject(string $subject): static
    {
        $this->subject = $subject;
        return $this;
    }

    public function getSubject(): ?string
    {
        return $this->subject;
    }

    public function setWhoisHost(string $host): static
    {
        $this->whoisHost = $host;
        return $this;
    }

    public function getWhoisHost(): ?string
    {
        return $this->whoisHost;
    }

    public function setModuleType(string $module): static
    {
        $this->moduleType = $module;
        return $this;
    }

    public function getModuleType(): ?string
    {
        return $this->moduleType;
    }
}
