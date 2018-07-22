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
        $groups = $this->groupsFromText($response->getText());
        if ($this->isFlat) {
            $finalGroup = [];
            foreach ($groups as $group) {
                $finalGroup = array_merge_recursive($finalGroup, $group);
            }
            return $finalGroup;
        }
        return GroupHelper::findDomainGroup(
            $groups,
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
        $group = [];
        $headerLines = [];
        $lines = ParserHelper::splitLines($text);
        $lines[] = '';
        foreach ($lines as $line) {
            $trimChars = " \t\n\r\0\x0B";
            $isComment = mb_strlen($line) != mb_strlen(ltrim($line, "%#;:"));
            $line = ltrim(rtrim($line, "%#*=$trimChars"), "%#*=;$trimChars");
            $headerLine = trim($line, ':[]');
            $headerLines[] = $headerLine;
            $kv = $isComment ? [] : explode(':', $line, 2);
            if (count($kv) == 2) {
                $k = trim($kv[0], ".:$trimChars");
                $v = trim($kv[1], ":$trimChars");
                $group = array_merge_recursive($group, [$k => ltrim($v, ".")]);
                continue;
            }
            if (empty($group[$this->headerKey]) && count($group) > 0) {
                $group[$this->headerKey] = $this->findBestHeader($headerLines);
            }
            if (count($group) > 1) {
                $groups[] = array_filter($group);
                $group = [];
                $headerLines = [$headerLine];
            }
        }
        return $groups;
    }

    /**
     * @param string[] $lines
     * @return int|null|string
     */
    protected function findBestHeader($lines)
    {
        $map = [];
        $empty = 1;
        foreach ($lines as $line) {
            if (empty($line)) {
                $empty++;
                continue;
            }
            if ($empty > 0) {
                $empty = 0;
                $map[$line] = mb_strlen($line) + count(preg_split('~\s+~ui', $line));
            }
        }
        $header = '';
        if (!empty($map)) {
            asort($map, SORT_NUMERIC);
            $header = key($map);
        }
        return $header;
    }
}
