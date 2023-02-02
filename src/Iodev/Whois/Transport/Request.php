<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

class Request
{
    public const DEFAULT_PORT = 43;

    protected string $host = '';
    protected int $port = self::DEFAULT_PORT;
    protected string $query = '';
    protected int $timeout = 0;
    protected bool $cancelled = false;


    public function setHost(string $host): static
    {
        $this->host = $host;
        return $this;
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function setPort(int $port): static
    {
        $this->port = $port;
        return $this;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function setQuery(string $query): static
    {
        $this->query = $query;
        return $this;
    }

    public function getQuery(): string
    {
        return $this->query;
    }


    public function setTimeout(int $timeout): static
    {
        $this->timeout = $timeout;
        return $this;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }


    public function setCancelled(bool $yes): static
    {
        $this->cancelled = $yes;
        return $this;
    }

    public function getCancelled(): bool
    {
        return $this->cancelled;
    }
}
