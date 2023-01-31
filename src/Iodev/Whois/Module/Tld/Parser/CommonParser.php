<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parser;

use Iodev\Whois\Selection\GroupFilter;
use Iodev\Whois\Module\Tld\TldInfo;
use Iodev\Whois\Module\Tld\TldInfoScoreCalculator;
use Iodev\Whois\Module\Tld\TldResponse;
use Iodev\Whois\Module\Tld\TldParser;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Tool\ParserTool;

class CommonParser extends TldParser
{
    public function __construct(
        protected CommonParserOpts $opts,
        protected TldInfoScoreCalculator $infoScoreCalculator,
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
        return $this->getOpts()->isFlat ? TldParser::COMMON_FLAT : TldParser::COMMON;
    }

    public function setConfig(array $cfg): static
    {
        foreach ($cfg as $k => $v) {
            $this->opts->{$k} = $v;
        }
        return $this;
    }

    public function parseResponse(TldResponse $response): ?TldInfo
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

    protected function createDomainInfo(TldResponse $response, array $data, array $extra = []): TldInfo
    {
        $domainName = $data['domainName'] ?? '';
        return new TldInfo(
            $response,
            $data['parserType'] ?? '',
            $domainName,
            $domainName ? $this->domainTool->toUnicode($domainName) : '',
            $data['whoisServer'] ?? '',
            $data['nameServers'] ?? [],
            $data['creationDate'] ?? 0,
            $data['expirationDate'] ?? 0,
            $data['updatedDate'] ?? 0,
            $data['states'] ?? '',
            $data['owner'] ?? '',
            $data['registrar'] ?? '',
            $data['dnssec'] ?? '',
            $extra,
        );
    }

    protected function createGroupFilter(): GroupFilter
    {
        return new GroupFilter(
            $this->domainTool,
            $this->dateTool,
        );
    }

    protected function filterFrom(TldResponse $response): GroupFilter
    {
        $text = $response->text;


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
        return $filter->filterIsDomain($response->domain, $this->getOpts()->domainKeys)
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
