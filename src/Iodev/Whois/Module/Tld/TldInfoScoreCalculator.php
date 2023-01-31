<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

class TldInfoScoreCalculator
{
    public function isValuable(TldInfo $info, array $badFirstStatesDict = []): bool
    {
        $firstState = count($info->states) > 0
            ? $info->states[array_key_first($info->states)]
            : ''
        ;
        $firstState = mb_strtolower(trim($firstState));
        if (!empty($badFirstStatesDict[$firstState])) {
            return false;
        }
        if (empty($info->domainName)) {
            return false;
        }
        return count($info->states) > 0
            || count($info->nameServers) > 0
            || !empty($info->owner)
            || $info->creationDate > 0
            || $info->expirationDate > 0
            || !empty($info->registrar)
        ;
    }

    public function calcRank(TldInfo $info): int
    {
        return (!empty($info->domainName) ? 100 : 0)
            + (count($info->nameServers) > 0 ? 20 : 0)
            + ($info->creationDate > 0 ? 6 : 0)
            + ($info->expirationDate > 0 ? 6 : 0)
            + ($info->updatedDate > 0 ? 6 : 0)
            + (count($info->states) > 0 ? 4 : 0)
            + (!empty($info->owner) ? 4 : 0)
            + (!empty($info->registrar) ? 3 : 0)
            + (!empty($info->whoisServer) ? 2 : 0)
            + (!empty($info->dnssec) ? 2 : 0)
        ;
    }
}
