<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Helpers\GroupHelper;
use Iodev\Whois\Info;
use Iodev\Whois\Response;

class CommonParser implements IParser
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
        $info->whoisServer = GroupHelper::getAsciiServer($group, [
            "whois",
            "whoisserver",
            "whois server",
            "registrar whois server",
        ]);
        $info->nameServers = GroupHelper::getAsciiServers($group, [
            "nameserver",
            "name server",
        ]);
        $info->creationDate = GroupHelper::getUnixtime($group, [
            "creationdate",
            "creation date",
        ]);
        $info->expirationDate = GroupHelper::getUnixtime($group, [
            "expirationdate",
            "expiration date",
            "registrar registration expiration date",
        ]);
        $info->states = $this->parseStates($group);
        $info->owner = GroupHelper::matchFirst($group, [
            "organization",
            "tech organization",
            "admin organization",
        ]);
        $info->registrar = GroupHelper::matchFirst($group, [ "registrar" ]);
        
        return $info;
    }

    /**
     * @param array $group
     * @return string[]
     */
    private function parseStates($group)
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
                $states[] = mb_strtoupper($m[1]);
            }
        }
        return $states;
    }
}
