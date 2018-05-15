<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Modules\Tld\DomainResponse;
use Iodev\Whois\Modules\Tld\Parser;
use Iodev\Whois\Helpers\GroupHelper;

class CommonParser extends Parser
{
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
        $group = $this->groupFrom($response);
        if (!$group) {
            return null;
        }
        $data = [
            "domainName" => GroupHelper::getAsciiServer($group, $this->domainKeys),
            "whoisServer" => GroupHelper::getAsciiServer($group, $this->whoisServerKeys),
            "nameServers" => GroupHelper::getAsciiServersComplex($group, $this->nameServersKeys, $this->nameServersKeysGroups),
            "creationDate" => GroupHelper::getUnixtime($group, $this->creationDateKeys),
            "expirationDate" => GroupHelper::getUnixtime($group, $this->expirationDateKeys),
            "owner" => GroupHelper::matchFirst($group, $this->ownerKeys),
            "registrar" => GroupHelper::matchFirst($group, $this->registrarKeys),
            "states" => $this->parseStates(GroupHelper::matchFirst($group, $this->statesKeys)),
        ];
        if (empty($data["domainName"])) {
            return null;
        }
        $states = $data["states"];
        $firstState = !empty($states) ? mb_strtolower(trim($states[0])) : "";
        if (!empty($this->notRegisteredStatesDict[$firstState])) {
            return null;
        }
        if (empty($states)
            && empty($data["nameServers"])
            && empty($data["owner"])
            && empty($data["creationDate"])
            && empty($data["expirationDate"])
            && empty($data["registrar"])
        ) {
            return null;
        }
        $data["owner"] = is_array($data["owner"]) ? reset($data["owner"]) : $data["owner"];
        return new DomainInfo($response, $data);
    }

    /**
     * @param DomainResponse $response
     * @return array
     */
    protected function groupFrom(DomainResponse $response)
    {
        if ($this->isFlat) {
            return $this->groupFromText($response->getText());
        }
        return GroupHelper::findDomainGroup(
            $this->groupsFromText($response->getText()),
            $response->getDomain(),
            $this->domainKeys
        );
    }

    /**
     * @param string $text
     * @return array
     */
    protected function groupsFromText($text)
    {
        $groups = [];
        $prevEmptyGroupText = '';
        $splits = preg_split('/([\s\t]*\r?\n){2,}/', $text);
        foreach ($splits as $groupText) {
            $group = $this->groupFromText($groupText, $prevEmptyGroupText);
            if (count($group) > 1) {
                $groups[] = $group;
                $prevEmptyGroupText = '';
            } else {
                $prevEmptyGroupText = $groupText;
            }
        }
        return $groups;
    }

    /**
     * @param string $text
     * @param string $prevEmptyGroupText
     * @return array
     */
    protected function groupFromText($text, $prevEmptyGroupText = '')
    {
        $group = [];
        preg_match_all('/^[ \t]*([^%#\r\n:]+):[ \t]*(.*?)\s*$/mui', $text, $m);
        foreach ($m[1] as $index => $key) {
            $key = trim($key);
            if ($key != 'http' && $key != 'https') {
                $group = array_merge_recursive($group, [$key => $m[2][$index]]);
            }
        }
        return $group;
    }

    /**
     * @param string[]|string $rawstates
     * @param bool $removeExtra
     * @return string[]
     */
    protected function parseStates($rawstates, $removeExtra = true)
    {
        $states = [];
        $rawstates = is_array($rawstates) ? $rawstates : [ strval($rawstates) ];
        foreach ($rawstates as $rawstate) {
            if (preg_match('/^\s*(.+)\s*/ui', $rawstate, $m)) {
                $state = mb_strtolower($m[1]);
                $states[] = $removeExtra
                    ? trim(preg_replace('~\(.+?\)|http.+~ui', '', $state))
                    : $state;
            }
        }
        if (count($states) == 1) {
            return $this->splitJoinedStates($states[0]);
        }
        return $states;
    }

    /**
     * @param string $stateStr
     * @return string[]
     */
    protected function splitJoinedStates($stateStr)
    {
        $splits = [];
        $rawsplits = explode(",", $stateStr);
        foreach ($rawsplits as $rawsplit) {
            $state = trim($rawsplit);
            if (!empty($state)) {
                $splits[] = $state;
            }
        }
        return $splits;
    }
}
