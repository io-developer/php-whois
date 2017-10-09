<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\Info;
use Iodev\Whois\Helpers\DateHelper;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Response;
use Iodev\Whois\ResponseGroup;

class ComParser implements IParser
{
    /**
     * @param Response $response
     * @return Info
     */
    public function parseResponse(Response $response)
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
        $info->expirationDate = $this->parseExpirationDate($group);
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
                "domain" => 1,
                "domainname" => 1,
                "domain name" => 1,
            ])
        );
    }
    
    /**
     * @param ResponseGroup $group
     * @return string
     */
    private function parseWhoisServer(ResponseGroup $group)
    {
        return DomainHelper::toAscii(
            $group->getByKeyDict([
                "whois" => 1,
                "whoisserver" => 1,
                "whois server" => 1,
                "registrar whois server" => 1,
            ])
        );
    }
    
    /**
     * @param ResponseGroup $group
     * @return string[]
     */
    private function parseNameServers(ResponseGroup $group)
    {
        $nservers = [];
        $arr = $group->getByKeyDict([
            "nameserver" => 1,
            "name server" => 1,
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
                "creationdate" => 1,
                "creation date" => 1,
            ])
        );
    }
    
    /**
     * @param ResponseGroup $group
     * @return int
     */
    private function parseExpirationDate(ResponseGroup $group)
    {
        return DateHelper::parseDate(
            $group->getByKeyDict([
                "expirationdate" => 1,
                "expiration date" => 1,
                "registrar registration expiration date" => 1,
            ])
        );
    }
    
    /**
     * @param ResponseGroup $group
     * @return string[]
     */
    private function parseStates(ResponseGroup $group)
    {
        $states = [];
        $rawstates = $group->getByKeyDict([
            "status" => 1,
            "domainstatus" => 1,
            "domain status" => 1,
        ]);
        $rawstates = is_array($rawstates) ? $rawstates : [ "".$rawstates ];
        foreach ($rawstates as $state) {
            if (preg_match('/^\s*([\w-]+)/ui', $state, $m)) {
                $states[] = mb_strtoupper($m[1]);
            }
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
            "organization" => 1,
            "tech organization" => 1,
            "admin organization" => 1,
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
