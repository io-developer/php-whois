<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\DomainInfo;
use Iodev\Whois\Response;
use Iodev\Whois\Helpers\GroupHelper;

class CommonParser implements IParser
{
    /**
     * @param Response $response
     * @return DomainInfo
     */
    public function parseResponse(Response $response)
    {
        $domainKeys = [ "domain", "domainname", "domain name" ];
        $groups = GroupHelper::groupsFromResponseText($response->getText());
        $group = GroupHelper::findDomainGroup($groups, $response->getDomain(), $domainKeys);
        if (!$group) {
            return null;
        }
        return new DomainInfo($response, [
            "domainName" => GroupHelper::getAsciiServer($group, $domainKeys),
            "whoisServer" => GroupHelper::getAsciiServer($group, [
                "whois",
                "whoisserver",
                "whois server",
                "registrar whois server",
            ]),
            "nameServers" => GroupHelper::getAsciiServers($group, [
                "nameserver",
                "name server",
                "nserver",
            ]),
            "creationDate" => GroupHelper::getUnixtime($group, [
                "creationdate",
                "creation date",
                "domain registration date",
                "created",
            ]),
            "expirationDate" => GroupHelper::getUnixtime($group, [
                "expirationdate",
                "expiration date",
                "domain expiration date",
                "registry expiry date",
                "registrar registration expiration date",
                "paid-till",
            ]),
            "owner" => GroupHelper::matchFirst($group, [
                "organization",
                "registrant organization",
                "registrant",
                "tech organization",
                "admin organization",
                "org",
            ]),
            "registrar" => GroupHelper::matchFirst($group, [
                "registrar",
                "registrar name",
                "sponsoring registrar",
            ]),
            "states" => $this->parseStates($group),
        ]);
    }

    /**
     * @param array $group
     * @return string[]
     */
    private function parseStates($group)
    {
        $states = $this->parseStatesIndividual($group);
        if (!empty($states)) {
            return $states;
        }
        return $this->parseStatesJoined($group);
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
            if (preg_match('/^\s*([\w-]+)/ui', $state, $m)) {
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
        $stateStr = GroupHelper::matchFirst($group, [ "state" ]);
        $states = [];
        $rawstates = explode(",", $stateStr);
        foreach ($rawstates as $state) {
            $states[] = mb_strtolower(trim($state));
        }
        return $states;
    }
}
