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
        "tech organization",
        "admin organization",
        "org",
    ];

    protected $registrarKeys = [
        "registrar",
        "registrar name",
        "sponsoring registrar",
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
        $states = $this->parseStates($group);
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
     * @param array $group
     * @param bool $removeExtra
     * @return string[]
     */
    private function parseStates($group, $removeExtra = true)
    {
        $states = $this->parseStatesIndividual($group);
        if (empty($states)) {
            $states = $this->parseStatesJoined($group);
        }
        if ($removeExtra) {
            $filtered = [];
            foreach ($states as $state) {
                $filtered[] = trim(preg_replace('~\(.+?\)|http.+~ui', '', $state));
            }
            return $filtered;
        }
        return $states;
    }

    /**
     * @param array $group
     * @return string[]
     */
    private function parseStatesIndividual($group)
    {
        $states = [];
        $rawstates = GroupHelper::matchFirst($group, [
            "status",
            "domainstatus",
            "domain status",
        ]);
        $rawstates = is_array($rawstates) ? $rawstates : [ "".$rawstates ];
        foreach ($rawstates as $state) {
            if (preg_match('/^\s*(.+)\s*/ui', $state, $m)) {
                $states[] = mb_strtolower($m[1]);
            }
        }
        return $states;
    }

    /**
     * @param array $group
     * @return string[]
     */
    private function parseStatesJoined($group)
    {
        $stateStr = GroupHelper::matchFirst($group, [
            "state",
        ]);
        $states = [];
        $rawstates = explode(",", $stateStr);
        foreach ($rawstates as $state) {
            $state = trim($state);
            if (!empty($state)) {
                $states[] = mb_strtolower($state);
            }
        }
        return $states;
    }
}
