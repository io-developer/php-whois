<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\GroupFilter;
use Iodev\Whois\Helpers\ParserHelper;
use Iodev\Whois\Modules\Tld\TldInfo;
use Iodev\Whois\Modules\Tld\TldResponse;
use Iodev\Whois\Modules\Tld\TldParser;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;

class CommonParser extends TldParser
{
    /** @var string */
    protected $headerKey = 'HEADER';

    /** @var bool */
    protected $isFlat = false;

    /** @var array */
    protected $domainKeys = [ "domain name" ];

    /** @var array */
    protected $whoisServerKeys = [ "whois server" ];

    /** @var array */
    protected $nameServersKeys = [ "name server" ];

    /** @var array */
    protected $nameServersKeysGroups = [ [ "ns 1", "ns 2", "ns 3", "ns 4" ] ];

    /** @var array */
    protected $dnssecKeys = [ "dnssec" ];

    /** @var array */
    protected $creationDateKeys = [ "creation date" ];

    /** @var array */
    protected $expirationDateKeys = [ "expiration date" ];

    /** @var array */
    protected $updatedDateKeys = [ "updated date" ];

    /** @var array */
    protected $ownerKeys = [ "owner-organization" ];

    /** @var array */
    protected $registrarKeys = [ "registrar" ];

    /** @var array */
    protected $statesKeys = [ "domain status" ];

    /** @var array */
    protected $notRegisteredStatesDict = [ "not registered" => 1 ];

    /** @var string */
    protected $emptyValuesDict = [
        "" => 1,
        "not.defined." => 1,
    ];

    public function __construct(
        protected DomainTool $domainTool,
        protected DateTool $dateTool,
    ) {}

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->isFlat ? TldParser::COMMON_FLAT : TldParser::COMMON;
    }

    public function setConfig(array $cfg): static
    {
        foreach ($cfg as $k => $v) {
            $this->{$k} = $v;
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
                ->selectKeys($this->domainKeys)
                ->mapDomain()
                ->removeEmpty()
                ->getFirst(''),

            "whoisServer" => (string)$sel->clean()
                ->selectKeys($this->whoisServerKeys)
                ->mapAsciiServer()
                ->removeEmpty()
                ->getFirst(''),

            "nameServers" => $sel->clean()
                ->selectKeys($this->nameServersKeys)
                ->selectKeyGroups($this->nameServersKeysGroups)
                ->mapAsciiServer()
                ->removeEmpty()
                ->removeDuplicates(11)
                ->getAll(),

            "dnssec" => (string)$sel->clean()
                ->selectKeys($this->dnssecKeys)
                ->removeEmpty()
                ->sort(SORT_ASC)
                ->getFirst(''),

            "creationDate" => $sel->clean()
                ->selectKeys($this->creationDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(0),

            "expirationDate" => $sel->clean()
                ->selectKeys($this->expirationDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(0),

            "updatedDate" => $sel->clean()
                ->selectKeys($this->updatedDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(0),

            "owner" => (string)$sel->clean()
                ->selectKeys($this->ownerKeys)
                ->getFirst(''),

            "registrar" => (string)$sel->clean()
                ->selectKeys($this->registrarKeys)
                ->getFirst(''),

            "states" => $sel->clean()
                ->selectKeys($this->statesKeys)
                ->transform(fn($items) => $this->transformItemsIntoStates($items))
                ->removeEmpty()
                ->removeDuplicates()
                ->getAll(),
        ];
        $info = $this->createDomainInfo($response, $data, [
            'groups' => $rootFilter->getGroups(),
            'rootFilter' => $rootFilter,
        ]);
        return $info->isValuable($this->notRegisteredStatesDict) ? $info : null;
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
        $groups = $this->groupsFromText($response->text);
        $filter = $this->createGroupFilter()
            ->setGroups($groups)
            ->useIgnoreCase(true)
            ->useMatchFirstOnly(true)
            ->handleEmpty($this->emptyValuesDict);

        if ($this->isFlat) {
            return $filter->mergeGroups();
        }
        return $filter->filterIsDomain($response->domain, $this->domainKeys)
            ->useFirstGroup();
    }

    protected function groupsFromText(string $text): array
    {
        $lines = ParserHelper::splitLines($text);
        return ParserHelper::linesToGroups($lines, $this->headerKey);
    }

    protected function transformItemsIntoStates(array $items): array
    {
        $states = [];
        foreach ($items as $item) {
            foreach (ParserHelper::parseStates($item) as $k => $state) {
                if (is_int($k) && is_string($state)) {
                    $states[] = $state;
                }
            }
        }
        return $states;
    }
}
