<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\DomainInfo;
use Iodev\Whois\Helpers\DateHelper;
use Iodev\Whois\Response;
use Iodev\Whois\Helpers\GroupHelper;

class CommonParser implements IParser
{
    protected $domainKeys = [
        "domain",
        "domainname",
        "domain name",
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
    ];

    protected $creationDateKeys = [
        "creationdate",
        "creation date",
        "domain registration date",
        "registration time",
        "created",
        "created on",
        "registered",
        "record created",
    ];

    protected $expirationDateKeys = [
        "expirationdate",
        "expiration date",
        "domain expiration date",
        "registry expiry date",
        "registrar registration expiration date",
        "expiration time",
        "paid-till",
    ];

    protected $ownerKeys = [
        "organization",
        "registrant organization",
        "registrant contact organisation",
        "registrant",
        "registrant name",
        "tech organization",
        "admin organization",
        "org",
        "holder",
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
        $states = $this->parseStates(GroupHelper::matchFirst($group, $this->statesKeys));
        $firstState = !empty($states) ? mb_strtolower(trim($states[0])) : "";
        $notFoundStatesDict = [
            "no object found" => 1,
            "available" => 1,
            "free" => 1,
        ];
        if (!empty($states) && !empty($notFoundStatesDict[$firstState])) {
            return null;
        }
        return new DomainInfo($response, [
            "domainName" => GroupHelper::getAsciiServer($group, $this->domainKeys),
            "whoisServer" => GroupHelper::getAsciiServer($group, $this->whoisServerKeys),
            "nameServers" => GroupHelper::getAsciiServers($group, $this->nameServersKeys),
            "creationDate" => GroupHelper::getUnixtime($group, $this->creationDateKeys),
            "expirationDate" => GroupHelper::getUnixtime($group, $this->expirationDateKeys),
            "owner" => GroupHelper::matchFirst($group, $this->ownerKeys),
            "registrar" => GroupHelper::matchFirst($group, $this->registrarKeys),
            "states" => $states,
        ]);
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
