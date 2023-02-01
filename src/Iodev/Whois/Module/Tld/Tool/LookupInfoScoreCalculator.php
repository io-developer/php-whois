<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Tool;

use Iodev\Whois\Module\Tld\Dto\LookupInfo;

class LookupInfoScoreCalculator
{
    public function isValuable(LookupInfo $info, array $badFirstStatesDict = []): bool
    {
        $states = $info->getStatuses();
        $firstState = count($states) > 0 ? reset($states) : '';
        $firstState = mb_strtolower(trim($firstState));

        if (!empty($badFirstStatesDict[$firstState])) {
            return false;
        }
        if (empty($info->getDomainName())) {
            return false;
        }
        return count($states) > 0
            || count($info->getNameServers()) > 0
            || !empty($info->getRegistrant())
            || $info->getCreatedTs() > 0
            || $info->getExpiresTs() > 0
            || !empty($info->getRegistrar())
        ;
    }

    public function calcRank(LookupInfo $info): int
    {
        return (!empty($info->getDomainName()) ? 100 : 0)
            + (count($info->getNameServers()) > 0 ? 20 : 0)
            + ($info->getCreatedTs() > 0 ? 6 : 0)
            + ($info->getExpiresTs() > 0 ? 6 : 0)
            + ($info->getUpdatedTs() > 0 ? 6 : 0)
            + (count($info->getStatuses()) > 0 ? 4 : 0)
            + (!empty($info->getRegistrant()) ? 4 : 0)
            + (!empty($info->getRegistrar()) ? 3 : 0)
            + (!empty($info->getWhoisHost()) ? 2 : 0)
            + (!empty($info->getDnssec()) ? 2 : 0)
        ;
    }
}
