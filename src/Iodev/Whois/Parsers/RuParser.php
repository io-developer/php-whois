<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\Helpers\GroupHelper;
use Iodev\Whois\DomainInfo;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Response;

class RuParser implements IParser
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
        return new DomainInfo([
            "response" => $response,
            "domainName" => GroupHelper::getAsciiServer($group, $domainKeys),
            "whoisServer" => "",
            "nameServers" => GroupHelper::getAsciiServers($group, [ "nserver" ]),
            "creationDate" => GroupHelper::getUnixtime($group, [ "created" ]),
            "expirationDate" => GroupHelper::getUnixtime($group, [ "paid-till" ]),
            "states" => $this->parseStates($group),
            "owner" => GroupHelper::matchFirst($group, [ "org" ]),
            "registrar" => GroupHelper::matchFirst($group, [ "registrar" ]),
        ]);
    }

    /**
     * @param array $group
     * @return string[]
     */
    private function parseStates($group)
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
