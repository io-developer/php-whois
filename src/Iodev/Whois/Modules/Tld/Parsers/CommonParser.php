<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\GroupFilter;
use Iodev\Whois\Helpers\ParserHelper;
use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Modules\Tld\DomainResponse;
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
    protected $creationDateKeys = [ "creation date" ];

    /** @var array */
    protected $expirationDateKeys = [ "expiration date" ];

    /** @var array */
    protected $ownerKeys = [ "owner-organization" ];

    /** @var array */
    protected $registrarKeys = [ "registrar" ];

    /** @var array */
    protected $statesKeys = [ "domain status" ];

    /** @var array */
    protected $notRegisteredStatesDict = [ "not registered" => 1 ];

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
     * @param DomainResponse $response
     * @return DomainInfo
     */
    public function parseResponse(DomainResponse $response)
    {
        $sel = $this->filterFrom($response)->toSelector();
        $data = [
            "domainName" => $sel->clean()
                ->selectKeys($this->domainKeys)
                ->mapAsciiServer()
                ->removeEmpty()
                ->getFirst(),

            "whoisServer" => $sel->clean()
                ->selectKeys($this->whoisServerKeys)
                ->mapAsciiServer()
                ->removeEmpty()
                ->getFirst(),

            "nameServers" => $sel->clean()
                ->selectKeys($this->nameServersKeys)
                ->selectKeyGroups($this->nameServersKeysGroups)
                ->mapAsciiServer()
                ->removeEmpty()
                ->removeDuplicates()
                ->getAll(),

            "creationDate" => $sel->clean()
                ->selectKeys($this->creationDateKeys)
                ->mapUnixTime()
                ->getFirst(),

            "expirationDate" => $sel->clean()
                ->selectKeys($this->expirationDateKeys)
                ->mapUnixTime()
                ->getFirst(),

            "owner" => $sel->clean()
                ->selectKeys($this->ownerKeys)
                ->getFirst(),

            "registrar" => $sel->clean()
                ->selectKeys($this->registrarKeys)
                ->getFirst(),

            "states" => $sel->clean()
                ->selectKeys($this->statesKeys)
                ->mapStates()
                ->getAll(),
        ];
        $info = new DomainInfo($response, $data);
        return $info->isValuable($this->notRegisteredStatesDict) ? $info : null;
    }

    /**
     * @param DomainResponse $response
     * @return GroupFilter
     */
    protected function filterFrom(DomainResponse $response)
    {
        $groups = $this->groupsFromText($response->getText());
        $filter = GroupFilter::create($groups)
            ->useIgnoreCase(true)
            ->useMatchFirstOnly(true);

        if ($this->isFlat) {
            return $filter->mergeGroups();
        }
        return $filter->filterIsDomain($response->getDomain(), $this->domainKeys)
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
