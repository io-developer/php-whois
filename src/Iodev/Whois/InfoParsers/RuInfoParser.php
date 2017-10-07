<?php

namespace Iodev\Whois\InfoParsers;

use Iodev\Whois\Info;
use Iodev\Whois\Helpers\DateHelper;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Response;
use Iodev\Whois\ResponseGroup;

class RuInfoParser implements IInfoParser
{
    /**
     * @param Response $response
     * @return Info
     */
    public function fromResponse(Response $response)
    {
        $group = $this->findGroup($response);
        if (!$group) {
            return null;
        }
        
        $info = new Info();
        $info->response = $response;
        $info->domainName = $this->parseDomainName($group);
        $info->domainNameUnicode = DomainHelper::toUnicode($info->domainName);
        $info->whoisServer = $this->parseWhoisServer($group);
        $info->nameServers = $this->parseNameServers($group);
        $info->creationDate = $this->parseCreationDate($group);
        $info->expirationDate = $this->_parseExpirationDate($group);
        $info->states = $this->parseStates($group);
        $info->owner = $this->parseOwner($group);
        $info->registrar = $this->parseRegistrar($group);
        
        return $info;
    }
    
    /**
     * @param Response $response
     * @return ResponseGroup
     */
    private function findGroup(Response $response)
    {
        foreach ($response->groups as $group) {
            $foundDomain = $this->parseDomainName($group);
            if ($foundDomain && DomainHelper::compareNames($foundDomain, $response->requestedDomain)) {
                return $group;
            }
        }
        return null;
    }
    
    /**
     * @param ResponseGroup $group
     * @return string
     */
    private function parseDomainName(ResponseGroup $group)
    {
        return DomainHelper::toAscii(
            $group->getByKeyDict([
                "domain" => 1
                , "domainname" => 1
                , "domain name" => 1
            ])
        );
    }
    
    /**
     * @param ResponseGroup $group
     * @return string
     */
    private function parseWhoisServer(ResponseGroup $group)
    {
        return "";
    }
    
    /**
     * @param ResponseGroup $group
     * @return string[]
     */
    private function parseNameServers(ResponseGroup $group)
    {
        $nservers = [];
        $arr = $group->getByKeyDict([
            "nserver" => 1
        ]);
        $arr = is_array($arr) ? $arr : [ "".$arr ];
        foreach ($arr as $nserv) {
            $nservers[] = DomainHelper::toAscii($nserv);
        }
        return $nservers;
    }
    
    /**
     * @param ResponseGroup $group
     * @return int
     */
    private function parseCreationDate(ResponseGroup $group)
    {
        return DateHelper::parseDate(
            $group->getByKeyDict([
                "created" => 1
            ])
        );
    }
    
    /**
     * @param ResponseGroup $group
     * @return int
     */
    private function _parseExpirationDate(ResponseGroup $group)
    {
        return DateHelper::parseDate(
            $group->getByKeyDict([
                "paid-till" => 1
            ])
        );
    }
    
    /**
     * @param ResponseGroup $group
     * @return string[]
     */
    private function parseStates(ResponseGroup $group)
    {
        $stateStr = $group->getByKeyDict([
            "state" => 1
        ]);
        $states = [];
        $rawstates = explode(",", $stateStr);
        foreach ($rawstates as $state) {
            $states[] = mb_strtoupper(trim($state));
        }
        return $states;
    }
    
    /**
     * @param ResponseGroup $group
     * @return string
     */
    private function parseOwner(ResponseGroup $group)
    {
        return $group->getByKeyDict([
            "org" => 1
        ]);
    }
    
    /**
     * @param ResponseGroup $group
     * @return string
     */
    private function parseRegistrar(ResponseGroup $group)
    {
        return $group->getByKeyDict([
            "registrar" => 1
        ]);
    }
}
