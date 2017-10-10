<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\Helpers\ResponseHelper;
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
        $groups = [];
        $oldGroups = ResponseHelper::contentToGroups($response->content);
        foreach ($oldGroups as $oldGroup) {
            $groups[] = $oldGroup->data;
        }

        $group = ResponseHelper::findDomainGroup($groups, $response->domain);
        if (!$group) {
            return null;
        }
        
        $info = new Info();
        $info->response = $response;
        $info->domainName = ResponseHelper::parseDomainName($group);
        $info->domainNameUnicode = DomainHelper::toUnicode($info->domainName);
        $info->whoisServer = "";
        $info->nameServers = ResponseHelper::parseNameServersAscii($group, [ "nserver" ]);
        $info->creationDate = ResponseHelper::parseDate($group, [ "created" ]);
        $info->expirationDate = ResponseHelper::parseDate($group, [ "paid-till" ]);
        $info->states = $this->parseStates($group);
        $info->owner = ResponseHelper::firstGroupMatch($group, [ "org" ]);
        $info->registrar = ResponseHelper::firstGroupMatch($group, [ "registrar" ]);

        return $info;
    }

    /**
     * @param array $group
     * @return string[]
     */
    private function parseStates($group)
    {
        $stateStr = ResponseHelper::firstGroupMatch($group, [ "state" ]);
        $states = [];
        $rawstates = explode(",", $stateStr);
        foreach ($rawstates as $state) {
            $states[] = mb_strtoupper(trim($state));
        }
        return $states;
    }
}
