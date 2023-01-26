<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\GroupFilter;
use Iodev\Whois\Modules\Tld\TldInfo;
use Iodev\Whois\Modules\Tld\TldResponse;
use Iodev\Whois\Modules\Tld\TldParser;

class BlockParser extends CommonParser
{
    /** @var array */
    protected $reservedDomainKeys = [ "Reserved name" ];

    /** @var array */
    protected $reservedDomainSubsets = [];

    /** @var array */
    protected $domainSubsets = [];

    /** @var array */
    protected $primarySubsets = [];

    /** @var array */
    protected $statesSubsets = [];

    /** @var array */
    protected $nameServersSubsets = [];

    /** @var array */
    protected $nameServersSparsedSubsets = [];

    /** @var array */
    protected $ownerSubsets = [];

    /** @var array */
    protected $registrarSubsets = [];

    /** @var array */
    protected $registrarReservedSubsets = [];

    /** @var array */
    protected $registrarReservedKeys = [];

    /** @var array */
    protected $contactSubsets = [];

    /** @var array */
    protected $contactOrgKeys = [];

    /** @var array */
    protected $registrarGroupKeys = [];

    /** @var array */
    protected $updatedDateExtraKeys = [ "changed" ];


    /** @var string */
    protected $matchedDomain = '';

    public function getType(): string
    {
        return TldParser::BLOCK;
    }

    public function parseResponse(TldResponse $response): ?TldInfo
    {
        $groups = $this->groupsFromText($response->text);
        $rootFilter = $this->createGroupFilter()
            ->setGroups($groups)
            ->useIgnoreCase(true)
            ->handleEmpty($this->emptyValuesDict)
            ->setHeaderKey($this->headerKey)
            ->setDomainKeys($this->domainKeys)
            ->setSubsetParams([
                '$domain' => $response->domain,
                '$domainUnicode' => $this->domainTool->toUnicode($response->domain),
            ]);

        $reserved = $rootFilter->cloneMe()
            ->filterHasSubsetOf($this->reservedDomainSubsets)
            ->toSelector()
            ->selectKeys($this->reservedDomainKeys)
            ->getFirst();

        $isReserved = !empty($reserved);

        $domainFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->domainSubsets);

        $primaryFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->primarySubsets)
            ->useFirstGroupOr($domainFilter->getFirstGroup());

        $data = [
            "parserType" => $this->getType(),
            "domainName" => $this->parseDomain($domainFilter) ?: ($isReserved ? $response->domain : ''),
            "states" => $this->parseStates($rootFilter, $primaryFilter),
            "nameServers" => $this->parseNameServers($rootFilter, $primaryFilter),
            "dnssec" => $this->parseDnssec($rootFilter, $primaryFilter),
            "owner" => $this->parseOwner($rootFilter, $primaryFilter) ?: ($isReserved ? $reserved : ''),
            "registrar" => $this->parseRegistrar($rootFilter, $primaryFilter),
            "creationDate" => $this->parseCreationDate($rootFilter, $primaryFilter),
            "expirationDate" => $this->parseExpirationDate($rootFilter, $primaryFilter),
            "updatedDate" => $this->parseUpdatedDate($rootFilter, $primaryFilter),
            "whoisServer" => $this->parseWhoisServer($rootFilter, $primaryFilter),
        ];

        $info = $this->createDomainInfo($response, $data, [
            'groups' => $groups,
            'rootFilter' => $rootFilter,
            'domainFilter' => $domainFilter,
            'primaryFilter' => $primaryFilter,
            'reserved' => $reserved,
        ]);
        return $isReserved || $info->isValuable($this->notRegisteredStatesDict) ? $info : null;
    }

    protected function parseDomain(GroupFilter $domainFilter): string
    {
        $sel = $domainFilter
            ->toSelector()
            ->selectKeys($this->domainKeys)
            ->removeEmpty();
        $this->matchedDomain = $sel->getFirst('');

        $domain = $sel->mapDomain()->removeEmpty()->getFirst('');
        if (!empty($domain)) {
            return $domain;
        }

        $sel = $domainFilter->cloneMe()
            ->filterHasHeader()
            ->toSelector()
            ->selectKeys([ 'name' ])
            ->removeEmpty();
        $this->matchedDomain = $sel->getFirst('');

        return $sel->mapDomain()->removeEmpty()->getFirst('');
    }

    protected function parseStates(GroupFilter $rootFilter, GroupFilter $primaryFilter): array
    {
        $states = $primaryFilter->toSelector()
            ->selectKeys($this->statesKeys)
            ->transform(fn($items) => $this->transformItemsIntoStates($items))
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();

        if (!empty($states)) {
            return $states;
        }

        $extraStates = [];
        if ($this->matchedDomain && preg_match('~is\s+(.+)$~', $this->matchedDomain, $m)) {
            $extraStates = [ $m[1] ];
        }
        return $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->statesSubsets)
            ->toSelector()
            ->selectItems($extraStates)
            ->selectKeys($this->statesKeys)
            ->transform(fn($items) => $this->transformItemsIntoStates($items))
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();
    }

    protected function parseNameServers(GroupFilter $rootFilter, GroupFilter $primaryFilter): array
    {
        $nameServers = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->nameServersSubsets)
            ->useFirstGroup()
            ->toSelector()
            ->selectKeys($this->nameServersKeys)
            ->selectKeyGroups($this->nameServersKeysGroups)
            ->mapAsciiServer()
            ->removeEmpty()
            ->getAll();

        $nameServers = $rootFilter->cloneMe()
            ->filterHasSubsetOf($this->nameServersSparsedSubsets)
            ->toSelector()
            ->useMatchFirstOnly(true)
            ->selectItems($nameServers)
            ->selectKeys($this->nameServersKeys)
            ->selectKeyGroups($this->nameServersKeysGroups)
            ->mapAsciiServer()
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();

        if (!empty($nameServers)) {
            return $nameServers;
        }
        return $primaryFilter->toSelector()
            ->useMatchFirstOnly(true)
            ->selectKeys($this->nameServersKeys)
            ->selectKeyGroups($this->nameServersKeysGroups)
            ->mapAsciiServer()
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();
    }

    protected function parseDnssec(GroupFilter $rootFilter, GroupFilter $primaryFilter): string
    {
        $dnssec = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->nameServersSubsets)
            ->useFirstGroup()
            ->toSelector()
            ->selectKeys($this->dnssecKeys)
            ->removeEmpty()
            ->sort(SORT_ASC)
            ->getFirst()
        ;
        if (empty($dnssec)) {
            $dnssec = $primaryFilter->toSelector()
                ->selectKeys($this->dnssecKeys)
                ->removeEmpty()
                ->sort(SORT_ASC)
                ->getFirst('');
        }
        if (empty($dnssec)) {
            $dnssec = $rootFilter->toSelector()
                ->selectKeys($this->dnssecKeys)
                ->removeEmpty()
                ->sort(SORT_ASC)
                ->getFirst('');
        }
        return $dnssec;
    }

    protected function parseOwner(GroupFilter $rootFilter, GroupFilter $primaryFilter): string
    {
        $owner = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->ownerSubsets)
            ->toSelector()
            ->selectKeys($this->ownerKeys)
            ->getFirst('');

        if (empty($owner)) {
            $owner = $primaryFilter->toSelector()
                ->selectKeys($this->ownerKeys)
                ->getFirst('');
        }
        if (!empty($owner)) {
            $owner = $rootFilter->cloneMe()
                ->setSubsetParams(['$id' => $owner])
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->contactSubsets)
                ->toSelector()
                ->selectKeys($this->contactOrgKeys)
                ->selectItems([ $owner ])
                ->removeEmpty()
                ->getFirst('');
        }
        return (string)$owner;
    }

    protected function parseRegistrar(GroupFilter $rootFilter, GroupFilter $primaryFilter): string
    {
        $registrar = $primaryFilter->toSelector()
            ->useMatchFirstOnly(true)
            ->selectKeys($this->registrarKeys)
            ->getFirst();

        if (empty($registrar)) {
            $registrarFilter = $rootFilter->cloneMe()
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->registrarSubsets);

            $registrar = $registrarFilter->toSelector()
                ->selectKeys($this->registrarGroupKeys)
                ->getFirst();
        }
        if (empty($registrar) && !empty($registrarFilter)) {
            $registrar = $registrarFilter->filterHasHeader()
                ->toSelector()
                ->selectKeys([ 'name' ])
                ->getFirst();
        }
        if (empty($registrar)) {
            $registrar = $primaryFilter->toSelector()
                ->selectKeys($this->registrarKeys)
                ->getFirst();
        }

        $regFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->registrarReservedSubsets);

        $regId = $regFilter->toSelector()
            ->selectKeys($this->registrarReservedKeys)
            ->getFirst();

        if (!empty($regId) && (empty($registrar) || $regFilter->getFirstGroup() != $primaryFilter->getFirstGroup())) {
            $registrarOrg = $rootFilter->cloneMe()
                ->setSubsetParams(['$id' => $regId])
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->contactSubsets)
                ->toSelector()
                ->selectKeys($this->contactOrgKeys)
                ->getFirst();

            $owner = $this->parseOwner($rootFilter, $primaryFilter);
            $registrar = ($registrarOrg && $registrarOrg != $owner)
                ? $registrarOrg
                : $registrar;
        }

        return (string)$registrar;
    }

    protected function parseCreationDate(GroupFilter $rootFilter, GroupFilter $primaryFilter): int
    {
        return $this->parseDate(
            $rootFilter,
            $primaryFilter,
            $this->creationDateKeys,
            '~registered\s+on\b~ui'
        );
    }

    protected function parseExpirationDate(GroupFilter $rootFilter, GroupFilter $primaryFilter): int
    {
        return $this->parseDate(
            $rootFilter,
            $primaryFilter,
            $this->expirationDateKeys,
            '~registry\s+fee\s+due\s+on\b~ui'
        );
    }

    protected function parseUpdatedDate(GroupFilter $rootFilter, GroupFilter $primaryFilter): int
    {
        $ts = $this->parseDate($rootFilter, $primaryFilter, $this->updatedDateKeys);
        if ($ts) {
            return $ts;
        }
        return (int)$primaryFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetKeyOf($this->updatedDateExtraKeys)
            ->toSelector()
            ->selectKeys($this->updatedDateExtraKeys)
            ->mapUnixTime($this->getOption('inversedDateMMDD', false))
            ->removeEmpty()
            ->getFirst(0)
        ;
    }

    protected function parseDate(
        GroupFilter $rootFilter,
        GroupFilter $primaryFilter,
        array $keys,
        string $fallbackRegex = ''
    ): int {
        $time = $primaryFilter->toSelector()
            ->selectKeys($keys)
            ->mapUnixTime($this->getOption('inversedDateMMDD', false))
            ->getFirst(0)
        ;
        if (!empty($time)) {
            return $time;
        }
        $sel = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetKeyOf($keys)
            ->toSelector()
            ->selectKeys($keys)
        ;
        $time = $sel->cloneMe()
            ->mapUnixTime($this->getOption('inversedDateMMDD', false))
            ->getFirst(0)
        ;
        if (!empty($time)) {
            return $time;
        }
        if (empty($fallbackRegex)) {
            return 0;
        }
        foreach ($sel->getAll() as $str) {
            if ($str && preg_match($fallbackRegex, $str)) {
                $time = $this->dateTool->parseDateInText($str);
                if (!empty($time)) {
                    return $time;
                }
            }
        }
        return 0;
    }

    protected function parseWhoisServer(GroupFilter $rootFilter, GroupFilter $primaryFilter): string
    {
        return (string)$primaryFilter->toSelector()
            ->selectKeys($this->whoisServerKeys)
            ->mapAsciiServer()
            ->getFirst('');
    }
}
