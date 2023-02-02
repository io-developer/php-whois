<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

class Request
{
    public const DEFAULT_PORT = 43;

    protected readonly string $host;
    protected readonly int $port;
    protected readonly string $query;
    protected readonly int $timeout;


    public function setHost(string $host): static
    {
        $this->host = $host;
        return $this;
    }

    public function getHost(): string
    {
        return $this->host ?? '';
    }

    public function setPort(int $port): static
    {
        $this->port = $port;
        return $this;
    }

    public function getPort(): int
    {
        return $this->port ?? static::DEFAULT_PORT;
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


    public function setTimeout(int $timeout): static
    {
        $this->timeout = $timeout;
        return $this;
    }

    public function getTimeout(): int
    {
        return $this->timeout ?? 0;
    }
}
