<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\DomainInfo;
use Iodev\Whois\Parser;
use Iodev\Whois\Response;
use Iodev\Whois\Helpers\GroupHelper;

class CommonParser extends Parser
{
    /** @var array */
    private $domainKeys = [ "domain name" ];

    /** @var array */
    private $whoisServerKeys = [ "whois server" ];

    /** @var array */
    private $nameServersKeys = [ "name server" ];

    /** @var array */
    private $nameServersKeysGroups = [ [ "ns 1", "ns 2", "ns 3", "ns 4" ] ];

    /** @var array */
    private $creationDateKeys = [ "creation date" ];

    /** @var array */
    private $expirationDateKeys = [ "expiration date" ];

    /** @var array */
    private $ownerKeys = [ "owner-organization" ];

    /** @var array */
    private $registrarKeys = [ "registrar" ];

    /** @var array */
    private $statesKeys = [ "domain status" ];

    /** @var array */
    private $notRegisteredStatesDict = [ "not registered" => 1 ];

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
     * @param Response $response
     * @return DomainInfo
     */
    public function parseResponse(Response $response)
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
        return new DomainInfo($response, $data);
    }

    /**
     * @param Response $response
     * @return array
     */
    protected function groupFrom(Response $response)
    {
        $groups = GroupHelper::groupsFromText($response->getText());
        return GroupHelper::findDomainGroup($groups, $response->getDomain(), $this->domainKeys);
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
