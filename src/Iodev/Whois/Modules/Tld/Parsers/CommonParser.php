<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\GroupFilter;
use Iodev\Whois\Helpers\ParserHelper;
use Iodev\Whois\Modules\Tld\TldInfo;
use Iodev\Whois\Modules\Tld\TldResponse;
use Iodev\Whois\Modules\Tld\TldParser;

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

    /**
     * @return string
     */
    public function getType()
    {
        return $this->isFlat ? TldParser::COMMON_FLAT : TldParser::COMMON;
    }

    /**
     * @param array $cfg
     * @return $this
     */
    public function setConfig($cfg)
    {
        foreach ($cfg as $k => $v) {
            $this->{$k} = $v;
        }
        return $this;
    }

    /**
     * @param TldResponse $response
     * @return TldInfo
     */
    public function parseResponse(TldResponse $response)
    {
        $rootFilter = $this->filterFrom($response);
        $sel = $rootFilter->toSelector();
        $data = [
            "parserType" => $this->getType(),

            "domainName" => $sel->clean()
                ->selectKeys($this->domainKeys)
                ->mapDomain()
                ->removeEmpty()
                ->getFirst(''),

            "whoisServer" => $sel->clean()
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

            "dnssec" => $sel->clean()
                ->selectKeys($this->dnssecKeys)
                ->removeEmpty()
                ->sort(SORT_ASC)
                ->getFirst(''),

            "creationDate" => $sel->clean()
                ->selectKeys($this->creationDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(''),

            "expirationDate" => $sel->clean()
                ->selectKeys($this->expirationDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(''),

            "updatedDate" => $sel->clean()
                ->selectKeys($this->updatedDateKeys)
                ->mapUnixTime($this->getOption('inversedDateMMDD', false))
                ->getFirst(''),

            "owner" => $sel->clean()
                ->selectKeys($this->ownerKeys)
                ->getFirst(''),

            "registrar" => $sel->clean()
                ->selectKeys($this->registrarKeys)
                ->getFirst(''),

            "states" => $sel->clean()
                ->selectKeys($this->statesKeys)
                ->mapStates()
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

    /**
     * @param TldResponse $response
     * @param array $data
     * @param array $options
     * @return TldInfo
     */
    protected function createDomainInfo(TldResponse $response, array $data, $options = [])
    {
        return new TldInfo($response, $data, $options);
    }

    /**
     * @return GroupFilter
     */
    protected function createGroupFilter(): GroupFilter
    {
        return new GroupFilter();
    }

    /**
     * @param TldResponse $response
     * @return GroupFilter
     */
    protected function filterFrom(TldResponse $response)
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

    /**
     * @param string $text
     * @return array
     */
    protected function groupsFromText($text)
    {
        $lines = ParserHelper::splitLines($text);
        return ParserHelper::linesToGroups($lines, $this->headerKey);
    }
}
