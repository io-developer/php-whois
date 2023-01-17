<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

/**
 * @property string[] $nameServers
 * @property string[] $states
 */
class TldInfo
{
    public function __construct(
        public readonly TldResponse $response,
        public readonly string $parserType = '',
        public readonly string $domainName = '',
        public readonly string $domainNameUnicode = '',
        public readonly string $whoisServer = '',
        public readonly array $nameServers = [],
        public readonly int $creationDate = 0,
        public readonly int $expirationDate = 0,
        public readonly int $updatedDate = 0,
        public readonly array $states = [],
        public readonly string $owner = '',
        public readonly string $registrar = '',
        public readonly string $dnssec = '',
        public readonly array $extra = [],
    ) {}

    public function isValuable(array $badFirstStatesDict = []): bool
    {
        $firstState = count($this->states) > 0
            ? $this->states[array_key_first($this->states)]
            : ''
        ;
        $firstState = mb_strtolower(trim($firstState));
        if (!empty($badFirstStatesDict[$firstState])) {
            return false;
        }
        if (empty($this->domainName)) {
            return false;
        }
        return count($this->states) > 0
            || count($this->nameServers) > 0
            || !empty($this->owner)
            || $this->creationDate > 0
            || $this->expirationDate > 0
            || !empty($this->registrar)
        ;
    }

    public function calcValuation(): int
    {
        return (!empty($this->domainName) ? 100 : 0)
            + (count($this->nameServers) > 0 ? 20 : 0)
            + ($this->creationDate > 0 ? 6 : 0)
            + ($this->expirationDate > 0 ? 6 : 0)
            + ($this->updatedDate > 0 ? 6 : 0)
            + (count($this->states) > 0 ? 4 : 0)
            + (!empty($this->owner) ? 4 : 0)
            + (!empty($this->registrar) ? 3 : 0)
            + (!empty($this->whoisServer) ? 2 : 0)
            + (!empty($this->dnssec) ? 2 : 0)
        ;
    }
}
