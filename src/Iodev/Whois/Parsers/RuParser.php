<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\Helpers\GroupHelper;
use Iodev\Whois\Info;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Response;

class RuParser implements IParser
{
    /**
     * @param Response $response
     * @return Info
     */
    public function parseResponse(Response $response)
    {
        $domainKeys = [ "domain", "domainname", "domain name" ];
        $groups = GroupHelper::groupsFromResponseText($response->getText());
        $group = GroupHelper::findDomainGroup($groups, $response->getDomain(), $domainKeys);
        if (!$group) {
            return null;
        }
        
        $info = new Info();
        $info->response = $response;
        $info->domainName = GroupHelper::getAsciiServer($group, $domainKeys);
        $info->domainNameUnicode = DomainHelper::toUnicode($info->domainName);
        $info->whoisServer = "";
        $info->nameServers = GroupHelper::getAsciiServers($group, [ "nserver" ]);
        $info->creationDate = GroupHelper::getUnixtime($group, [ "created" ]);
        $info->expirationDate = GroupHelper::getUnixtime($group, [ "paid-till" ]);
        $info->states = $this->parseStates($group);
        $info->owner = GroupHelper::matchFirst($group, [ "org" ]);
        $info->registrar = GroupHelper::matchFirst($group, [ "registrar" ]);

        return $info;
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
