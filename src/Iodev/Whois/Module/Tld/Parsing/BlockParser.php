<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parsing;

use Iodev\Whois\Module\Tld\Dto\LookupInfo;
use Iodev\Whois\Module\Tld\Dto\LookupResponse;
use Iodev\Whois\Selection\GroupFilter;
use Iodev\Whois\Module\Tld\Tool\LookupInfoScoreCalculator;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Tool\ParserTool;

class BlockParser extends CommonParser
{
    /** @var string */
    protected $matchedDomain = '';

    public function __construct(
        BlockParserOpts $opts,
        LookupInfoScoreCalculator $infoScoreCalculator,
        ParserTool $parserTool,
        DomainTool $domainTool,
        DateTool $dateTool,
    ) {
        parent::__construct(
            $opts,
            $infoScoreCalculator,
            $parserTool,
            $domainTool,
            $dateTool
        );
    }

    public function getType(): string
    {
        return ParserInterface::BLOCK;
    }

    public function getOpts(): BlockParserOpts
    {
        return $this->opts;
    }

    public function parseResponse(LookupResponse $response): ?LookupInfo
    {
        $groups = $this->groupsFromText($response->text);
        $rootFilter = $this->createGroupFilter()
            ->setGroups($groups)
            ->useIgnoreCase(true)
            ->handleEmpty($this->getOpts()->emptyValuesDict)
            ->setHeaderKey($this->getOpts()->headerKey)
            ->setDomainKeys($this->getOpts()->domainKeys)
            ->setSubsetParams([
                '$domain' => $response->domain,
                '$domainUnicode' => $this->domainTool->toUnicode($response->domain),
            ]);

        $reserved = $rootFilter->cloneMe()
            ->filterHasSubsetOf($this->getOpts()->reservedDomainSubsets)
            ->toSelector()
            ->selectKeys($this->getOpts()->reservedDomainKeys)
            ->getFirst();

        $isReserved = !empty($reserved);

        $domainFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->getOpts()->domainSubsets);

        $primaryFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->getOpts()->primarySubsets)
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
        return $isReserved || $this->infoScoreCalculator->isValuable($info, $this->getOpts()->notRegisteredStatesDict)
            ? $info
            : null
        ;
    }

    protected function parseDomain(GroupFilter $domainFilter): string
    {
        $sel = $domainFilter
            ->toSelector()
            ->selectKeys($this->getOpts()->domainKeys)
            ->removeEmpty()
        ;
        $this->matchedDomain = $sel->getFirst('');

        $domain = $sel->mapDomain()->removeEmpty()->getFirst('');
        if (!empty($domain)) {
            return $domain;
        }

        $sel = $domainFilter->cloneMe()
            ->filterHasHeader()
            ->toSelector()
            ->selectKeys([ 'name' ])
            ->removeEmpty()
        ;
        $this->matchedDomain = $sel->getFirst('');

        return $sel->mapDomain()->removeEmpty()->getFirst('');
    }

    protected function parseStates(GroupFilter $rootFilter, GroupFilter $primaryFilter): array
    {
        $states = $primaryFilter->toSelector()
            ->selectKeys($this->getOpts()->statesKeys)
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
            ->filterHasSubsetOf($this->getOpts()->statesSubsets)
            ->toSelector()
            ->selectItems($extraStates)
            ->selectKeys($this->getOpts()->statesKeys)
            ->transform(fn($items) => $this->transformItemsIntoStates($items))
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();
    }

    protected function parseNameServers(GroupFilter $rootFilter, GroupFilter $primaryFilter): array
    {
        $nameServers = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->getOpts()->nameServersSubsets)
            ->useFirstGroup()
            ->toSelector()
            ->selectKeys($this->getOpts()->nameServersKeys)
            ->selectKeyGroups($this->getOpts()->nameServersKeysGroups)
            ->mapAsciiServer()
            ->removeEmpty()
            ->getAll();

        $nameServers = $rootFilter->cloneMe()
            ->filterHasSubsetOf($this->getOpts()->nameServersSparsedSubsets)
            ->toSelector()
            ->useMatchFirstOnly(true)
            ->selectItems($nameServers)
            ->selectKeys($this->getOpts()->nameServersKeys)
            ->selectKeyGroups($this->getOpts()->nameServersKeysGroups)
            ->mapAsciiServer()
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();

        if (!empty($nameServers)) {
            return $nameServers;
        }
        return $primaryFilter->toSelector()
            ->useMatchFirstOnly(true)
            ->selectKeys($this->getOpts()->nameServersKeys)
            ->selectKeyGroups($this->getOpts()->nameServersKeysGroups)
            ->mapAsciiServer()
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();
    }

    protected function parseDnssec(GroupFilter $rootFilter, GroupFilter $primaryFilter): string
    {
        $dnssec = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->getOpts()->nameServersSubsets)
            ->useFirstGroup()
            ->toSelector()
            ->selectKeys($this->getOpts()->dnssecKeys)
            ->removeEmpty()
            ->sort(SORT_ASC)
            ->getFirst()
        ;
        if (empty($dnssec)) {
            $dnssec = $primaryFilter->toSelector()
                ->selectKeys($this->getOpts()->dnssecKeys)
                ->removeEmpty()
                ->sort(SORT_ASC)
                ->getFirst('');
        }
        if (empty($dnssec)) {
            $dnssec = $rootFilter->toSelector()
                ->selectKeys($this->getOpts()->dnssecKeys)
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
            ->filterHasSubsetOf($this->getOpts()->ownerSubsets)
            ->toSelector()
            ->selectKeys($this->getOpts()->ownerKeys)
            ->getFirst('');

        if (empty($owner)) {
            $owner = $primaryFilter->toSelector()
                ->selectKeys($this->getOpts()->ownerKeys)
                ->getFirst('');
        }
        if (!empty($owner)) {
            $owner = $rootFilter->cloneMe()
                ->setSubsetParams(['$id' => $owner])
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->getOpts()->contactSubsets)
                ->toSelector()
                ->selectKeys($this->getOpts()->contactOrgKeys)
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
            ->selectKeys($this->getOpts()->registrarKeys)
            ->getFirst();

        if (empty($registrar)) {
            $registrarFilter = $rootFilter->cloneMe()
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->getOpts()->registrarSubsets);

            $registrar = $registrarFilter->toSelector()
                ->selectKeys($this->getOpts()->registrarGroupKeys)
                ->getFirst();
        }
        if (empty($registrar) && !empty($registrarFilter)) {
            $registrar = $registrarFilter->filterHasHeader()
                ->toSelector()
                ->selectKeys(['name'])
                ->getFirst();
        }
        if (empty($registrar)) {
            $registrar = $primaryFilter->toSelector()
                ->selectKeys($this->getOpts()->registrarKeys)
                ->getFirst();
        }

        $regFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->getOpts()->registrarReservedSubsets);

        $regId = $regFilter->toSelector()
            ->selectKeys($this->getOpts()->registrarReservedKeys)
            ->getFirst();

        if (!empty($regId) && (empty($registrar) || $regFilter->getFirstGroup() != $primaryFilter->getFirstGroup())) {
            $registrarOrg = $rootFilter->cloneMe()
                ->setSubsetParams(['$id' => $regId])
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->getOpts()->contactSubsets)
                ->toSelector()
                ->selectKeys($this->getOpts()->contactOrgKeys)
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
            $this->getOpts()->creationDateKeys,
            '~registered\s+on\b~ui'
        );
    }

    protected function parseExpirationDate(GroupFilter $rootFilter, GroupFilter $primaryFilter): int
    {
        return $this->parseDate(
            $rootFilter,
            $primaryFilter,
            $this->getOpts()->expirationDateKeys,
            '~registry\s+fee\s+due\s+on\b~ui'
        );
    }

    protected function parseUpdatedDate(GroupFilter $rootFilter, GroupFilter $primaryFilter): int
    {
        $ts = $this->parseDate($rootFilter, $primaryFilter, $this->getOpts()->updatedDateKeys);
        if ($ts) {
            return $ts;
        }
        return (int)$primaryFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetKeyOf($this->getOpts()->updatedDateExtraKeys)
            ->toSelector()
            ->selectKeys($this->getOpts()->updatedDateExtraKeys)
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
            ->selectKeys($this->getOpts()->whoisServerKeys)
            ->mapAsciiServer()
            ->getFirst('');
    }
}
