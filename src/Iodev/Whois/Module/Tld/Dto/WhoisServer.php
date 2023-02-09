<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Dto;

use Iodev\Whois\Module\Tld\Parsing\ParserInterface;

class WhoisServer
{
    protected string $tld = '';
    
    /** @var string[] */
    protected array $tldParts = [];

    /** @var string[] */
    protected array $tldPartsInv = [];

    protected string $host = '';
    protected int $port = 43;
    protected bool $centralized = false;
    protected ?ParserInterface $parser = null;
    protected string $queryFormat = '';
    protected int $priority = 0;

    public function setTld(string $tld): static
    {
        $normalizedTld = trim(mb_strtolower($tld), '.');

        $this->tld = rtrim('.' . $normalizedTld, '.');
        $this->tldParts = explode('.', $normalizedTld);
        $this->tldPartsInv = array_reverse($this->tldParts);

        return $this;
    }

    public function getTld(): string
    {
        return $this->tld;
    }

    /**
     * @return string[]
     */
    public function getTldParts(): array
    {
        return $this->tldParts;
    }

    /**
     * @return string[]
     */
    public function getTldPartsInversed(): array
    {
        return $this->tldPartsInv;
    }

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

    public function setPriority(int $priority): static
    {
        $this->priority = $priority;
        return $this;
    }

    public function getPriority(): int
    {
        return $this->priority;
    }

    public function setCentralized(bool $centralized): static
    {
        $this->centralized = $centralized;
        return $this;
    }

    public function getCentralized(): bool
    {
        return $this->centralized;
    }

    public function setQueryFormat(string $fmt): static
    {
        $this->queryFormat = $fmt;
        return $this;
    }

    public function getQueryFormat(): string
    {
        return $this->queryFormat;
    }

    public function setParser(ParserInterface $parser): static
    {
        $this->parser = $parser;
        return $this;
    }

    public function getParser(): ?ParserInterface
    {
        return $this->parser;
    }
}
