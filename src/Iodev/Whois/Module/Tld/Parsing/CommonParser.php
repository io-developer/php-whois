<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parsing;

use Iodev\Whois\Module\Tld\Dto\LookupInfo;
use Iodev\Whois\Module\Tld\Dto\LookupResponse;
use Iodev\Whois\Module\Tld\Tool\LookupInfoScoreCalculator;
use Iodev\Whois\Selection\GroupFilter;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Tool\ParserTool;

class CommonParser extends ParserInterface
{
    public function __construct(
        protected CommonParserOpts $opts,
        protected LookupInfoScoreCalculator $infoScoreCalculator,
        protected ParserTool $parserTool,
        protected DomainTool $domainTool,
        protected DateTool $dateTool,
    ) {}

    public function getOpts(): CommonParserOpts
    {
        return $this->opts;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->getOpts()->isFlat ? ParserInterface::COMMON_FLAT : ParserInterface::COMMON;
    }

    public function setConfig(array $cfg): static
    {
        foreach ($cfg as $k => $v) {
            $this->opts->{$k} = $v;
        }
        return $this;
    }

    public function parseResponse(LookupResponse $response): ?LookupInfo
    {
        $rootFilter = $this->filterFrom($response);
        $sel = $rootFilter->toSelector();
        $data = [
            "parserType" => $this->getType(),

            "domainName" => (string)$sel->clean()
                ->selectKeys($this->getOpts()->domainKeys)
                ->mapDomain()
                ->removeEmpty()
                ->getFirst(''),

            "whoisServer" => (string)$sel->clean()
                ->selectKeys($this->getOpts()->whoisServerKeys)
                ->mapAsciiServer()
                ->removeEmpty()
                ->getFirst(''),

            "nameServers" => $sel->clean()
                ->selectKeys($this->getOpts()->nameServersKeys)
                ->selectKeyGroups($this->getOpts()->nameServersKeysGroups)
                ->mapAsciiServer()
                ->removeEmpty()
                ->removeDuplicates()
                ->getAll(),

            "dnssec" => (string)$sel->clean()
                ->selectKeys($this->getOpts()->dnssecKeys)
                ->removeEmpty()
                ->sort(SORT_ASC)
                ->getFirst(''),

            "creationDate" => $sel->clean()
                ->selectKeys($this->getOpts()->creationDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(0),

            "expirationDate" => $sel->clean()
                ->selectKeys($this->getOpts()->expirationDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(0),

            "updatedDate" => $sel->clean()
                ->selectKeys($this->getOpts()->updatedDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(0),

            "owner" => (string)$sel->clean()
                ->selectKeys($this->getOpts()->ownerKeys)
                ->getFirst(''),

            "registrar" => (string)$sel->clean()
                ->selectKeys($this->getOpts()->registrarKeys)
                ->getFirst(''),

            "states" => $sel->clean()
                ->selectKeys($this->getOpts()->statesKeys)
                ->transform(fn($items) => $this->transformItemsIntoStates($items))
                ->removeEmpty()
                ->removeDuplicates()
                ->getAll(),
        ];
        $info = $this->createDomainInfo($response, $data, [
            'groups' => $rootFilter->getGroups(),
            'rootFilter' => $rootFilter,
        ]);

        // var_dump([
        //     'RAW INFO',
        //     'domainName' => $info->domainName,
        //     'whoisServer' => $info->whoisServer,
        //     'domainKeys' => $this->getOpts()->domainKeys,
        //     'sel getGroups' => $sel->getGroups(),
        // ]);

        // var_dump([
        //     "selectKeys" => $sel->clean()
        //         ->selectKeys($this->getOpts()->domainKeys),
        // ]);
        
        return $this->infoScoreCalculator->isValuable($info, $this->getOpts()->notRegisteredStatesDict)
            ? $info
            : null
        ;
    }

    protected function createDomainInfo(LookupResponse $response, array $data, array $extra = []): LookupInfo
    {
        $domainName = $data['domainName'] ?? '';
        return $this->createInfo()
            ->setResponse($response)
            ->setParserType($data['parserType'] ?? '')
            ->setDomain($domainName)
            ->setDomainUnicode($domainName ? $this->domainTool->toUnicode($domainName) : '')
            ->setWhoisHost($data['whoisServer'] ?? '')
            ->setNameServers($data['nameServers'] ?? [])
            ->setCreatedTs($data['creationDate'] ?? 0)
            ->setExpiresTs($data['expirationDate'] ?? 0)
            ->setUpdatedTs($data['updatedDate'] ?? 0)
            ->setStatuses($data['states'] ?? [])
            ->setRegistrant($data['owner'] ?? '')
            ->setRegistrar($data['registrar'] ?? '')
            ->setDnssec($data['dnssec'] ?? '')
            ->setExtra($extra)
        ;
    }

    protected function createInfo(): LookupInfo
    {
        return new LookupInfo();
    }

    protected function createGroupFilter(): GroupFilter
    {
        return new GroupFilter(
            $this->domainTool,
            $this->dateTool,
        );
    }

    protected function filterFrom(LookupResponse $response): GroupFilter
    {
        $text = $response->getOutput();


        // var_dump([
        //     'getType' => $this->getType(),
        //     '$this->getOpts()->isFlat' => $this->getOpts()->isFlat,
        // ]);

        if ($this->getOpts()->isFlat) {
            $text = $this->parserTool->removeEmptyLines($text);

            // var_dump([
            //     '$text' => $text,
            // ]);
        }

        $groups = $this->groupsFromText($text);
        $filter = $this->createGroupFilter()
            ->setGroups($groups)
            ->useIgnoreCase(true)
            ->useMatchFirstOnly(true)
            ->handleEmpty($this->getOpts()->emptyValuesDict);

        if ($this->getOpts()->isFlat) {
            return $filter->mergeGroups();
        }
        return $filter->filterIsDomain($response->getDomain(), $this->getOpts()->domainKeys)
            ->useFirstGroup();
    }

    protected function groupsFromText(string $text): array
    {
        $lines = $this->parserTool->splitLines($text);
        return $this->parserTool->linesToGroups($lines, $this->getOpts()->headerKey);
    }

    protected function transformItemsIntoStates(array $items): array
    {
        $states = [];
        foreach ($items as $item) {
            foreach ($this->parserTool->parseStates($item) as $k => $state) {
                if (is_int($k) && is_string($state)) {
                    $states[] = $state;
                }
            }
        }
        return $states;
    }
}
