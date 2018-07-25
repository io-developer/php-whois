<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\GroupFilter;
use Iodev\Whois\Helpers\ParserHelper;
use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Helpers\GroupHelper;
use Iodev\Whois\Modules\Tld\DomainResponse;

class BlockParser extends CommonParser
{
    /** @var array */
    protected $domainSubsets = [];

    /** @var array */
    protected $primarySubsets = [];

    /** @var array */
    protected $statesSubsets = [];

    /** @var array */
    protected $nameServersSubsets = [];

    /** @var array */
    protected $nameServersSparsedSubsets = [];

    /** @var array */
    protected $ownerSubsets = [];

    /** @var array */
    protected $registrarSubsets = [];

    /** @var array */
    protected $registrarReservedSubsets = [];

    /** @var array */
    protected $registrarReservedKeys = [];

    /** @var array */
    protected $contactSubsets = [];

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
        $filter = GroupFilter::create()
            ->setGroups($this->groupsFromText($response->getText()))
            ->setHeaderKey($this->headerKey)
            ->setDomainKeys($this->domainKeys)
            ->setSubsetParams([ '$domain' => $response->getDomain() ]);

        $domainGroup = $filter->filterHasSubsetOf($this->domainSubsets, true)
            ->getFirstGroup();

        $domain = GroupHelper::getAsciiServer($domainGroup, $this->domainKeys);
        if (empty($domain) && !empty($domainGroup[$this->headerKey])) {
            $domain = GroupHelper::getAsciiServer($domainGroup, ['name']);
        }
        if (empty($domain)) {
            return null;
        }

        // States
        $primaryGroup = $filter->filterHasSubsetOf($this->primarySubsets, true)
            ->useFirstGroupOr($domainGroup)
            ->getFirstGroup();

        $states = ParserHelper::parseStates(GroupHelper::matchFirst($primaryGroup, $this->statesKeys));
        if (empty($states)) {
            $statesGroup = $filter->filterHasSubsetOf($this->statesSubsets, true)
                ->getFirstGroup();

            $states = ParserHelper::parseStates(GroupHelper::matchFirst($statesGroup, $this->statesKeys));
        }
        $firstState = !empty($states) ? mb_strtolower(trim($states[0])) : "";
        if (!empty($this->notRegisteredStatesDict[$firstState])) {
            return null;
        }

        // NameServers
        $nsGroup = $filter->filterHasSubsetOf($this->nameServersSubsets, true)
            ->getFirstGroup();

        $nameServers = GroupHelper::getAsciiServersComplex($nsGroup, $this->nameServersKeys, $this->nameServersKeysGroups);

        // Sparsed ns
        $nsGroups = $filter->filterHasSubsetOf($this->nameServersSparsedSubsets)
            ->getGroups();

        foreach ($nsGroups as $nsGroup) {
            $list = GroupHelper::getAsciiServersComplex($nsGroup, $this->nameServersKeys, $this->nameServersKeysGroups);
            $nameServers = array_merge($nameServers, $list);
        }
        $nameServers = array_unique($nameServers);

        if (empty($nameServers)) {
            $nameServers = GroupHelper::getAsciiServersComplex($primaryGroup, $this->nameServersKeys, $this->nameServersKeysGroups);
        }

        $ownerGroup = $filter->filterHasSubsetOf($this->ownerSubsets, true)
            ->getFirstGroup();

        $registrar = GroupHelper::matchFirst($primaryGroup, $this->registrarKeys);
        if (empty($registrar)) {
            $registrarGroup = $filter->filterHasSubsetOf($this->registrarSubsets, true)
                ->getFirstGroup();

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

        if ($data["owner"]) {
            $group = $filter->cloneMe()
                ->setSubsetParams(['$id' => $data["owner"]])
                ->filterHasSubsetOf($this->contactSubsets, true)
                ->getFirstGroup();

            $ownerOrg = GroupHelper::matchFirst($group, $this->contactOrgKeys);
            $data["owner"] = $ownerOrg ? $ownerOrg : $data["owner"];
        }
        if (is_array($data["owner"])) {
            $data["owner"] = $data["owner"][0];
        }

        $regGroup = $filter->filterHasSubsetOf($this->registrarReservedSubsets, true)
            ->getFirstGroup();

        $regId = GroupHelper::matchFirst($regGroup, $this->registrarReservedKeys);
        $regId = is_array($regId) ? reset($regId) : $regId;

        if (!empty($regId) && (empty($registrar) || $regGroup != $primaryGroup)) {
            $regGroup = $filter->cloneMe()
                ->setSubsetParams(['$id' => $regId])
                ->filterHasSubsetOf($this->contactSubsets, true)
                ->getFirstGroup();

            $registrarOrg = GroupHelper::matchFirst($regGroup, $this->contactOrgKeys);
            $data["registrar"] = ($registrarOrg && $registrarOrg != $data["owner"])
                ? $registrarOrg
                : $data["registrar"];
        }
        if (is_array($data["registrar"])) {
            $data["registrar"] = $data["registrar"][0];
        }

        if (empty($data["creationDate"])) {
            $group = $filter->filterHasSubsetKeyOf($this->creationDateKeys, true)
                ->getFirstGroup();

            $data["creationDate"] = GroupHelper::getUnixtime($group, $this->creationDateKeys);
        }

        if (empty($data["expirationDate"])) {
            $group = $filter->filterHasSubsetKeyOf($this->expirationDateKeys, true)
                ->getFirstGroup();

            $data["expirationDate"] = GroupHelper::getUnixtime($group, $this->expirationDateKeys);
        }

        return new DomainInfo($response, $data);
    }
}
