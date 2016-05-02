<?php

namespace iodev\whois\parsers;

use iodev\whois\helpers\DateHelper;
use iodev\whois\helpers\DomainHelper;
use iodev\whois\WhoisInfo;
use iodev\whois\IWhoisInfoParser;
use iodev\whois\WhoisResponse;
use iodev\whois\WhoisResponseGroup;

/**
 * @author Sergey Sedyshev
 */
class ComInfoParser implements IWhoisInfoParser
{
    /**
     * @param WhoisResponse $response
     * @return WhoisInfo
     */
    public function fromResponse( WhoisResponse $response )
    {
        $group = $this->_findGroup($response);
        if (!$group) {
            return null;
        }
        
        $info = new WhoisInfo();
        $info->response = $response;
        $info->domainName = $this->_parseDomainName($group);
        $info->domainNameUnicode = DomainHelper::toUnicode($info->domainName);
        $info->whoisServer = $this->_parseWhoisServer($group);
        $info->nameServers = $this->_parseNameServers($group);
        $info->creationDate = $this->_parseCreationDate($group);
        $info->expirationDate = $this->_parseExpirationDate($group);
        $info->states = $this->_parseStates($group);
        $info->owner = $this->_parseOwner($group);
        $info->registrar = $this->_parseRegistrar($group);
        
        return $info;
    }
    
    /**
     * @param WhoisResponse $response
     * @return WhoisResponseGroup
     */
    private function _findGroup( WhoisResponse $response )
    {
        foreach ($response->groups as $group) {
            $foundDomain = $this->_parseDomainName($group);
            if ($foundDomain && DomainHelper::compareNames($foundDomain, $response->requestedDomain)) {
                return $group;
            }
        }
        return null;
    }
    
    /**
     * @param WhoisResponseGroup $group
     * @return string
     */
    private function _parseDomainName( WhoisResponseGroup $group )
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
     * @param WhoisResponseGroup $group
     * @return string
     */
    private function _parseWhoisServer( WhoisResponseGroup $group )
    {
        return DomainHelper::toAscii(
            $group->getByKeyDict([
                "whois" => 1
                , "whoisserver" => 1
                , "whois server" => 1
                , "registrar whois server" => 1
            ])
        );
    }
    
    /**
     * @param WhoisResponseGroup $group
     * @return string[]
     */
    private function _parseNameServers( WhoisResponseGroup $group )
    {
        $nservers = [];
        $arr = $group->getByKeyDict([
            "nameserver" => 1
            , "name server" => 1
        ]);
        $arr = is_array($arr) ? $arr : [ "".$arr ];
        foreach ($arr as $nserv) {
            $nservers[] = DomainHelper::toAscii($nserv);
        }
        return $nservers;
    }
    
    /**
     * @param WhoisResponseGroup $group
     * @return int
     */
    private function _parseCreationDate( WhoisResponseGroup $group )
    {
        return DateHelper::parseDate(
            $group->getByKeyDict([
                "creationdate" => 1
                , "creation date" => 1
            ])
        );
    }
    
    /**
     * @param WhoisResponseGroup $group
     * @return int
     */
    private function _parseExpirationDate( WhoisResponseGroup $group )
    {
        return DateHelper::parseDate(
            $group->getByKeyDict([
                "expirationdate" => 1
                , "expiration date" => 1
                , "registrar registration expiration date" => 1
            ])
        );
    }
    
    /**
     * @param WhoisResponseGroup $group
     * @return string[]
     */
    private function _parseStates( WhoisResponseGroup $group )
    {
        $states = [];
        $rawstates = $group->getByKeyDict([
            "status" => 1
            , "domainstatus" => 1
            , "domain status" => 1
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
     * @param WhoisResponseGroup $group
     * @return string
     */
    private function _parseOwner( WhoisResponseGroup $group )
    {
        return $group->getByKeyDict([
            "organization" => 1
            , "tech organization" => 1
            , "admin organization" => 1
        ]);
    }
    
    /**
     * @param WhoisResponseGroup $group
     * @return string
     */
    private function _parseRegistrar( WhoisResponseGroup $group )
    {
        return $group->getByKeyDict([
            "registrar" => 1
        ]);
    }
}
