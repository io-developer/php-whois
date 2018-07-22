<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\ParserHelper;
use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Modules\Tld\DomainResponse;
use Iodev\Whois\Modules\Tld\TldParser;
use Iodev\Whois\Helpers\GroupHelper;

class CommonParser extends TldParser
{
    /** @var string */
    protected $headerKey = 'HEADER';

    /** @var bool */
    protected $isFlat = false;

    /** @var array */
    protected $domainKeys = [ "domain name" ];

    /** @var array */
    protected $whoisServerKeys = [ "whois server" ];

    /** @var array */
    protected $nameServersKeys = [ "name server" ];

    /** @var array */
    protected $nameServersKeysGroups = [ [ "ns 1", "ns 2", "ns 3", "ns 4" ] ];

    /** @var array */
    protected $creationDateKeys = [ "creation date" ];

    /** @var array */
    protected $expirationDateKeys = [ "expiration date" ];

    /** @var array */
    protected $ownerKeys = [ "owner-organization" ];

    /** @var array */
    protected $registrarKeys = [ "registrar" ];

    /** @var array */
    protected $statesKeys = [ "domain status" ];

    /** @var array */
    protected $notRegisteredStatesDict = [ "not registered" => 1 ];

    /**
     * @param array $cfg
     * @return $this
     */
    public function setConfig($cfg)
    {
        foreach ($cfg as $k => $v) {
            $this->{$k} = $v;
        }
        return $this;
    }

    /**
     * @param DomainResponse $response
     * @return DomainInfo
     */
    public function parseResponse(DomainResponse $response)
    {
        $group = $this->groupFrom($response);
        if (!$group) {
            return null;
        }
        $data = [
            "domainName" => GroupHelper::getAsciiServer($group, $this->domainKeys),
            "whoisServer" => GroupHelper::getAsciiServer($group, $this->whoisServerKeys),
            "nameServers" => GroupHelper::getAsciiServersComplex($group, $this->nameServersKeys, $this->nameServersKeysGroups),
            "creationDate" => GroupHelper::getUnixtime($group, $this->creationDateKeys),
            "expirationDate" => GroupHelper::getUnixtime($group, $this->expirationDateKeys),
            "owner" => GroupHelper::matchFirst($group, $this->ownerKeys),
            "registrar" => GroupHelper::matchFirst($group, $this->registrarKeys),
            "states" => ParserHelper::parseStates(GroupHelper::matchFirst($group, $this->statesKeys)),
        ];
        if (empty($data["domainName"])) {
            return null;
        }
        $states = $data["states"];
        $firstState = !empty($states) ? mb_strtolower(trim($states[0])) : "";
        if (!empty($this->notRegisteredStatesDict[$firstState])) {
            return null;
        }
        if (empty($states)
            && empty($data["nameServers"])
            && empty($data["owner"])
            && empty($data["creationDate"])
            && empty($data["expirationDate"])
            && empty($data["registrar"])
        ) {
            return null;
        }
        $data["owner"] = is_array($data["owner"]) ? reset($data["owner"]) : $data["owner"];
        return new DomainInfo($response, $data);
    }

    /**
     * @param DomainResponse $response
     * @return array
     */
    protected function groupFrom(DomainResponse $response)
    {
        if ($this->isFlat) {
            return $this->groupFromText($response->getText());
        }
        return GroupHelper::findDomainGroup(
            $this->groupsFromText($response->getText()),
            $response->getDomain(),
            $this->domainKeys
        );
    }

    /**
     * @param string $text
     * @return array
     */
    protected function groupsFromText($text)
    {
        $groups = [];
        $prevEmptyGroupText = '';
        $splits = preg_split('/([\s\t]*\r?\n){2,}/', $text);
        foreach ($splits as $groupText) {
            $group = $this->groupFromText($groupText, $prevEmptyGroupText);
            if (count($group) > 1) {
                $groups[] = $group;
                $prevEmptyGroupText = '';
            } else {
                $prevEmptyGroupText = $groupText;
            }
        }
        return $groups;
    }

    /**
     * @param string $text
     * @param string $prevEmptyGroupText
     * @return array
     */
    protected function groupFromText($text, $prevEmptyGroupText = '')
    {
        $group = [];
        $header = null;
        foreach (preg_split('~\r\n|[\r\n]~u', $text) as $line) {
            if (isset($header) && ltrim($line, '%#*') !== $line) {
                continue;
            }
            $split = explode(':', ltrim($line, "%#*:;= \t\n\r\0\x0B"), 2);
            $k = isset($split[0]) ? trim($split[0], ". \t\n\r\0\x0B") : '';
            $v = isset($split[1]) ? trim($split[1]) : '';
            if (strlen($k) && strlen($v)) {
                $group = array_merge_recursive($group, [ $k => ltrim($v, ".") ]);
                continue;
            }
            if (!isset($header)) {
                $k = trim($k, "%#*:;=[] \t\0\x0B");
                $header = strlen($k) ? $k : null;
            }
        }
        $headerAlt = trim($prevEmptyGroupText, "%#*:;=[]. \t\n\r\0\x0B");
        $header = isset($header) ? $header : $headerAlt;
        $header = ($headerAlt && strlen($headerAlt) < strlen($header)) ? $headerAlt : $header;
        $group = !empty($header)
            ? array_merge_recursive($group, [$this->headerKey => $header])
            : $group;

        if (count($group) == 1 && GroupHelper::matchFirst($group, $this->domainKeys)) {
            $group[$this->headerKey] = "domain";
        }
        if (count($group) == 1 && GroupHelper::matchFirst($group, $this->nameServersKeys)) {
            $group[$this->headerKey] = "nameservers";
        }

        return $group;
    }
}
