<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Helpers\GroupHelper;
use Iodev\Whois\Modules\Tld\DomainResponse;

class BlockParser extends CommonParser
{
    /** @var string */
    protected $headerKey = 'HEADER';

    /** @var array */
    protected $domainSubsets = [];

    /** @var array */
    protected $primarySubsets = [];

    /** @var array */
    protected $nameServersSubsets = [];

    /** @var array */
    protected $ownerSubsets = [];

    /** @var array */
    protected $registrarSubsets = [];

    /** @var array */
    protected $contactOrgKeys = [];

    /** @var array */
    protected $registrarGroupKeys = [];

    /**
     * @param DomainResponse $response
     * @return DomainInfo
     */
    public function parseResponse(DomainResponse $response)
    {
        $groups = $this->groupsFromText($response->getText());

        $params = [
            '$domain' => $response->getDomain(),
        ];

        $domainGroup = GroupHelper::findGroupHasSubsetOf($groups, $this->renderSubsets($this->domainSubsets, $params));
        $domain = GroupHelper::getAsciiServer($domainGroup, $this->domainKeys);
        if (empty($domain) && !empty($domainGroup[$this->headerKey])) {
            $domain = GroupHelper::getAsciiServer($domainGroup, ['name']);
        }
        if (empty($domain)) {
            return null;
        }

        // States
        $primaryGroup = GroupHelper::findGroupHasSubsetOf($groups, $this->renderSubsets($this->primarySubsets, $params));
        $primaryGroup = empty($primaryGroup) ? $domainGroup : $primaryGroup;

        $states = $this->parseStates(GroupHelper::matchFirst($primaryGroup, $this->statesKeys));
        $firstState = !empty($states) ? mb_strtolower(trim($states[0])) : "";
        if (!empty($this->notRegisteredStatesDict[$firstState])) {
            return null;
        }

        // NameServers
        $nameServersGroup = GroupHelper::findGroupHasSubsetOf($groups, $this->renderSubsets($this->nameServersSubsets, $params));
        $nameServers = GroupHelper::getAsciiServersComplex($nameServersGroup, $this->nameServersKeys, $this->nameServersKeysGroups);
        if (empty($nameServers)) {
            $nameServers = GroupHelper::getAsciiServersComplex($primaryGroup, $this->nameServersKeys, $this->nameServersKeysGroups);
        }

        $ownerGroup = GroupHelper::findGroupHasSubsetOf($groups, $this->renderSubsets($this->ownerSubsets, $params));

        $registrar = GroupHelper::matchFirst($primaryGroup, $this->registrarKeys);
        if (empty($registrar)) {
            $registrarGroup = GroupHelper::findGroupHasSubsetOf($groups, $this->renderSubsets($this->registrarSubsets, $params));
            $registrar = GroupHelper::matchFirst($registrarGroup, $this->registrarGroupKeys);
        }
        if (empty($registrar) && !empty($registrarGroup[$this->headerKey])) {
            $registrar = GroupHelper::matchFirst($registrarGroup, ['name']);
        }

        $data = [
            "domainName" => $domain,
            "whoisServer" => GroupHelper::getAsciiServer($primaryGroup, $this->whoisServerKeys),
            "creationDate" => GroupHelper::getUnixtime($primaryGroup, $this->creationDateKeys),
            "expirationDate" => GroupHelper::getUnixtime($primaryGroup, $this->expirationDateKeys),
            "nameServers" => $nameServers,
            "owner" => GroupHelper::matchFirst($ownerGroup, $this->ownerKeys),
            "registrar" => $registrar,
            "states" => $states,
        ];
        if (empty($data['owner'])) {
            $data['owner'] = GroupHelper::matchFirst($primaryGroup, $this->ownerKeys);
        }
        if (empty($data['registrar'])) {
            $data['registrar'] = GroupHelper::matchFirst($primaryGroup, $this->registrarKeys);
        }

        if (is_array($data["owner"])) {
            $data["owner"] = $data["owner"][0];
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

        $contactSubsets = [
            ["nic-hdl" => '$id'],
            ["nic-hdl-br" => '$id'],
            ["contact" => '$id'],
        ];

        if ($data["owner"]) {
            $group = GroupHelper::findGroupHasSubsetOf(
                $groups,
                $this->renderSubsets($contactSubsets, ['$id' => $data["owner"]])
            );
            $ownerOrg = GroupHelper::matchFirst($group, $this->contactOrgKeys);
            $data["owner"] = $ownerOrg
                ? $ownerOrg
                : $data["owner"];
        }
        if (is_array($data["owner"])) {
            $data["owner"] = $data["owner"][0];
        }

        $regGroup = GroupHelper::findGroupHasSubsetOf($groups, [
            ["nsset" => "", "billing-c" => ""],
            ["nsset" => "", "tech-c" => ""],
            ["billing-c" => ""],
            ["tech-c" => ""],
        ]);
        if ($regGroup && !empty($regGroup["billing-c"])) {
            $regId = $regGroup["billing-c"];
            $regId = is_array($regId) ? reset($regId) : $regId;
        } elseif ($regGroup && !empty($regGroup["tech-c"])) {
            $regId = $regGroup["tech-c"];
            $regId = is_array($regId) ? reset($regId) : $regId;
        }

        if (!empty($regId) && (empty($registrar) || $regGroup != $primaryGroup)) {
            $regGroup = GroupHelper::findGroupHasSubsetOf(
                $groups,
                $this->renderSubsets($contactSubsets, ['$id' => $regId])
            );
            $registrarOrg = GroupHelper::matchFirst($regGroup, $this->contactOrgKeys);
            $data["registrar"] = ($registrarOrg && $registrarOrg != $data["owner"])
                ? $registrarOrg
                : $data["registrar"];
        }
        if (is_array($data["registrar"])) {
            $data["registrar"] = $data["registrar"][0];
        }

        if (empty($data["creationDate"])) {
            $subsests = [];
            foreach ($this->creationDateKeys as $k) {
                $subsests[] = [$k => ""];
            }
            $group = GroupHelper::findGroupHasSubsetOf($groups, $subsests);
            $data["creationDate"] = GroupHelper::getUnixtime($group, $this->creationDateKeys);
        }

        if (empty($data["expirationDate"])) {
            $subsests = [];
            foreach ($this->expirationDateKeys as $k) {
                $subsests[] = [$k => ""];
            }
            $group = GroupHelper::findGroupHasSubsetOf($groups, $subsests);
            $data["expirationDate"] = GroupHelper::getUnixtime($group, $this->expirationDateKeys);
        }

        return new DomainInfo($response, $data);
    }

    /**
     * @param array $subsets
     * @param array $params
     * @return array
     */
    private function renderSubsets($subsets, $params)
    {
        array_walk_recursive($subsets, function(&$val) use ($params) {
            if (isset($params[$val])) {
                $val = $params[$val];
            }
        });
        return $subsets;
    }

    /**
     * @param string $text
     * @return array
     */
    protected function groupsFromText($text)
    {
        $groups = parent::groupsFromText($text);
        if (count($groups) < 2) {
            $altGroups = $this->altGroupsFromText($text);
            $groups = count($altGroups) > 1 ? $altGroups : $groups;
        }
        return $groups;
    }

    /**
     * @param string $text
     * @return array
     */
    protected function altGroupsFromText($text)
    {
        $groups = [];
        $group = [];
        $lines = preg_split('~\r\n|\r|\n~ui', $text);
        $lines[] = '';
        foreach ($lines as $line) {
            $line = trim($line, "%#*;= \t\n\r\0\x0B");
            $kv = explode(':', $line, 2);
            if (count($kv) == 2) {
                $k = trim($kv[0], ".: \t\n\r\0\x0B");
                $v = trim($kv[1], ": \t\n\r\0\x0B");
                $group[$k] = $v;
                continue;
            }
            if (!empty($group)) {
                $groups[] = $group;
                $group = [];
            }
            if (!isset($group[$this->headerKey])) {
                $group[$this->headerKey] = $line;
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
            $k = isset($split[0]) ? trim($split[0], ".\t\n\r\0\x0B") : '';
            $v = isset($split[1]) ? trim($split[1]) : '';
            if (strlen($k) && strlen($v)) {
                $group = array_merge_recursive($group, [ $k => $v ]);
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

        if (count($group) == 1) {
            foreach ($this->domainKeys as $k) {
                if (isset($group[$k])) {
                    $group[$this->headerKey] = "domain";
                    break;
                }
            }
        }
        return $group;
    }
}
