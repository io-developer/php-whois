<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

class Request
{
    public const DEFAULT_PORT = 43;

    protected string $state = RequestState::NEW;
    protected string $host = '';
    protected int $port = self::DEFAULT_PORT;
    protected string $query = '';
    protected int $timeout = 0;
    protected array $middlewareClasses = [];

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

    public function setState(string $state, bool $force = false): bool
    {
        if ((!empty($state) && $this->state === RequestState::NEW) || $force) {
            $this->state = $state;
            return true;
        }
        return false;
    }

    public function getState(): string
    {
        return $this->state;
    }

    public function canSend(): bool
    {
        return $this->state !== RequestState::CANCELLED
            && $this->state !== RequestState::ERROR
            && $this->state !== RequestState::MIDDLEWARE_ERROR
        ;
    }

    public function cancel(bool $force = false): bool
    {
        return $this->setState(RequestState::CANCELLED, $force);
    }

    public function complete(bool $force = false): bool
    {
        return $this->setState(RequestState::COMPLETED, $force);
    }

    /**
     * @param string[] $classNames
     */
    public function setMiddlewareClasses(array $classNames): static
    {
        $this->middlewareClasses = array_map(fn($item) => (string)$item, $classNames);
        return $this;
    }

    /**
     * @return string[]
     */
    public function getMiddlewareClasses(): array
    {
        return $this->middlewareClasses;
    }
}
