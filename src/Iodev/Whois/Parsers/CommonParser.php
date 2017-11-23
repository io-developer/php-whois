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
            "states" => $states,
        ]);
    }

    /**
     * @param array $group
     * @param bool $removeUrls
     * @return string[]
     */
    private function parseStates($group, $removeUrls = true)
    {
        $states = $this->parseStatesIndividual($group);
        if (empty($states)) {
            $states = $this->parseStatesJoined($group);
        }
        if ($removeUrls) {
            $filtered = [];
            foreach ($states as $state) {
                $filtered[] = trim(preg_replace('~\(?http.+\)?~ui', '', $state));
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
            $states[] = mb_strtolower(trim($state));
        }
        return $states;
    }
}
