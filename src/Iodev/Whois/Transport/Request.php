<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

use Iodev\Whois\Traits\TagContainerTrait;

class Request
{
    use TagContainerTrait;

    public const DEFAULT_PORT = 43;

    protected string $host = '';
    protected int $port = self::DEFAULT_PORT;
    protected string $query = '';
    protected int $timeout = 0;
    protected array $usedMiddlewareClasses = [];

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

    public function canSend(): bool
    {
        return !$this->hasAnyTag([
            RequestTag::CANCELLED,
            RequestTag::ERROR,
            RequestTag::MIDDLEWARE_ERROR,
        ]);
    }

    public function cancel(): static
    {
        return $this->tagWith(RequestTag::CANCELLED);
    }

    public function complete(): static
    {
        return $this->tagWith(RequestTag::COMPLETED);
    }

    /**
     * @param string[] $classNames
     */
    public function setUsedMiddlewareClasses(array $classNames): static
    {
        $this->usedMiddlewareClasses = array_map(fn($item) => (string)$item, $classNames);
        return $this;
    }

    /**
     * @return string[]
     */
    public function getUsedMiddlewareClasses(): array
    {
        return $this->usedMiddlewareClasses;
    }
}
