<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Dto;

class LookupResponse
{
    protected readonly string $domain;
    
    protected readonly string $host;

    protected readonly string $query;

    protected readonly string $output;


    public function setDomain(string $domain): static
    {
        $this->domain = $domain;
        return $this;
    }

    public function getDomain(): string
    {
        return $this->domain ?? '';
    }


    public function setHost(string $host): static
    {
        $this->host = $host;
        return $this;
    }

    public function getHost(): string
    {
        return $this->host ?? '';
    }


    public function setQuery(string $query): static
    {
        $this->query = $query;
        return $this;
    }

    public function getQuery(): string
    {
        return $this->query ?? '';
    }


    public function setOutput(string $output): static
    {
        $this->output = $output;
        return $this;
    }

    public function getOutput(): string
    {
        return $this->output ?? '';
    }
}
