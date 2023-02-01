<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Dto;

use \DateTimeImmutable;

class LookupInfo
{
    protected readonly string $domainName;
    protected readonly string $domainNameUnicode;
    protected readonly string $registrant;
    protected readonly string $registrar;
    protected readonly string $whoisHost;
    protected readonly array $nameServers;
    protected readonly array $statuses;
    protected readonly int $createdTs;
    protected readonly ?DateTimeImmutable $createdDatetime;
    protected readonly int $updatedTs;
    protected readonly ?DateTimeImmutable $updatedDatetime;
    protected readonly int $expiresTs;
    protected readonly ?DateTimeImmutable $expiresDatetime;
    protected readonly string $dnssec;

    // deprecated fields
    protected readonly LookupResponse $response;
    protected readonly string $parserType;
    protected readonly array $extra;


    public function setDomainName(string $name): static
    {
        $this->domainName = $name;
        return $this;
    }

    public function getDomainName(): string
    {
        return $this->domainName ?? '';
    }


    public function setDomainNameUnicode(string $name): static
    {
        $this->domainNameUnicode = $name;
        return $this;
    }

    public function getDomainNameUnicode(): string
    {
        return $this->domainNameUnicode ?? '';
    }


    public function setRegistrant(string $registrant): static
    {
        $this->registrant = $registrant;
        return $this;
    }

    public function getRegistrant(): string
    {
        return $this->registrant ?? '';
    }

    public function getOwner(): string
    {
        return $this->getRegistrant();
    }


    public function setRegistrar(string $registrar): static
    {
        $this->registrar = $registrar;
        return $this;
    }

    public function getRegistrar(): string
    {
        return $this->registrar ?? '';
    }


    public function setWhoisHost(string $host): static
    {
        $this->whoisHost = $host;
        return $this;
    }

    public function getWhoisHost(): string
    {
        return $this->whoisHost ?? '';
    }

    /**
     * @param string[] $servers
     */
    public function setNameServers(array $servers): static
    {
        $this->nameServers = $servers;
        return $this;
    }

    /**
     * @return string[]
     */
    public function getNameServers(): array
    {
        return $this->nameServers ?? [];
    }

    /**
     * @param string[] $statuses
     */
    public function setStatuses(array $statuses): static
    {
        $this->statuses = $statuses;
        return $this;
    }

    /**
     * @return string[]
     */
    public function getStatuses(): array
    {
        return $this->statuses ?? [];
    }

    /**
     * @return string[]
     */
    public function getStates(): array
    {
        return $this->getStatuses();
    }


    public function setCreatedTs(int $ts): static
    {
        $this->createdTs = $ts;
        $this->createdDatetime = $ts > 0
            ? (new DateTimeImmutable())->setTimestamp($ts)
            : null
        ;
        return $this;
    }

    public function getCreatedTs(): int
    {
        return $this->createdTs ?? 0;
    }

    public function getCreatedDatetime(): ?DateTimeImmutable
    {
        return $this->createdDatetime ?? null;
    }


    public function setUpdatedTs(int $ts): static
    {
        $this->updatedTs = $ts;
        $this->updatedDatetime = $ts > 0
            ? (new DateTimeImmutable())->setTimestamp($ts)
            : null
        ;
        return $this;
    }

    public function getUpdatedTs(): int
    {
        return $this->updatedTs ?? 0;
    }

    public function getUpdatedDatetime(): ?DateTimeImmutable
    {
        return $this->updatedDatetime ?? null;
    }


    public function setExpiresTs(int $ts): static
    {
        $this->expiresTs = $ts;
        $this->expiresDatetime = $ts > 0
            ? (new DateTimeImmutable())->setTimestamp($ts)
            : null
        ;
        return $this;
    }

    public function getExpiresTs(): int
    {
        return $this->expiresTs ?? 0;
    }

    public function getExpiresDatetime(): ?DateTimeImmutable
    {
        return $this->expiresDatetime ?? null;
    }


    public function setDnssec(string $dnssec): static
    {
        $this->dnssec = $dnssec;
        return $this;
    }

    public function getDnssec(): string
    {
        return $this->dnssec ?? '';
    }


    // deprecated fields

    public function setResponse(LookupResponse $response): static
    {
        $this->response = $response;
        return $this;
    }

    public function getResponse(): ?LookupResponse
    {
        return $this->response ?? null;
    }


    public function setParserType(string $parserType): static
    {
        $this->parserType = $parserType;
        return $this;
    }

    public function getParserType(): string
    {
        return $this->parserType ?? '';
    }


    public function setExtra(array $extra): static
    {
        $this->extra = $extra;
        return $this;
    }

    public function getExtra(): array
    {
        return $this->extra ?? [];
    }
}
