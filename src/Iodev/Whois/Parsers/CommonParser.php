<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\DomainInfo;
use Iodev\Whois\Response;
use Iodev\Whois\Helpers\GroupHelper;

class CommonParser implements IParser
{
    protected $domainKeys = [
        "domain",
        "domainname",
        "domain name",
        "query",
    ];

    protected $whoisServerKeys = [
        "whois",
        "whoisserver",
        "whois server",
        "registrar whois server",
    ];

    protected $nameServersKeys = [
        "nameserver",
        "name server",
        "nserver",
        "host name",
        "dns",
    ];

    protected $nameServersKeysGroups = [
        [ "ns 1", "ns 2", "ns 3", "ns 4" ],
    ];

    protected $creationDateKeys = [
        "creationdate",
        "creation date",
        "registration date",
        "domain registration date",
        "registration time",
        "created",
        "created on",
        "created date",
        "registered",
        "registered on",
        "registered date",
        "record created",
    ];

    protected $expirationDateKeys = [
        "expirationdate",
        "expiration date",
        "expiration time",
        "exp date",
        "domain expiration date",
        "registry expiry date",
        "registrar registration expiration date",
        "expiry",
        "paid-till",
    ];

    protected $ownerKeys = [
        "organization",
        "registrant organization",
        "registrant internationalized organization",
        "registrant contact organisation",
        "registrant",
        "registrant name",
        "org",
        "holder",
        "domain holder",
        "owner orgname",
        "owner name",
        "tech organization",
        "admin organization",
    ];

    protected $registrarKeys = [
        "registrar",
        "registrar name",
        "sponsoring registrar",
        "sponsoring registrar organization",
    ];

    protected $statesKeys = [
        "domain status",
        "domainstatus",
        "status",
        "state",
    ];

    protected $notRegisteredStatesDict = [
        "not registered" => 1,
        "no object found" => 1,
        "available" => 1,
        "free" => 1,
    ];

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
