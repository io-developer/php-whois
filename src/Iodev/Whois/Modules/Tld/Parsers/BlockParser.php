<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\GroupFilter;
use Iodev\Whois\Modules\Tld\DomainInfo;
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
        $groups = $this->groupsFromText($response->getText());
        $rootFilter = GroupFilter::create($groups)
            ->useIgnoreCase(true)
            ->setHeaderKey($this->headerKey)
            ->setDomainKeys($this->domainKeys)
            ->setSubsetParams([ '$domain' => $response->getDomain() ]);

        $domainFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->domainSubsets);

        $primaryFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->primarySubsets)
            ->useFirstGroupOr($domainFilter->getFirstGroup());

        // Domain
        $domain = $domainFilter->toSelector()
            ->selectKeys($this->domainKeys)
            ->mapAsciiServer()
            ->removeEmpty()
            ->getFirst();

        if (empty($domain)) {
            $domain = $domainFilter->cloneMe()
                ->filterHasHeader()
                ->toSelector()
                ->selectKeys([ 'name' ])
                ->mapAsciiServer()
                ->removeEmpty()
                ->getFirst();
        }

        // States
        $states = $primaryFilter->toSelector()
            ->selectKeys($this->statesKeys)
            ->mapStates()
            ->getAll();

        if (empty($states)) {
            $states = $rootFilter->cloneMe()
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->statesSubsets)
                ->toSelector()
                ->selectKeys($this->statesKeys)
                ->mapStates()
                ->getAll();
        }

        // NameServers
        $nameServers = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->nameServersSubsets)
            ->useFirstGroup()
            ->toSelector()
            ->selectKeys($this->nameServersKeys)
            ->selectKeyGroups($this->nameServersKeysGroups)
            ->mapAsciiServer()
            ->removeEmpty()
            ->getAll();

        // Sparsed NameServers
        $nameServers = $rootFilter->cloneMe()
            ->filterHasSubsetOf($this->nameServersSparsedSubsets)
            ->toSelector()
            ->useMatchFirstOnly(true)
            ->selectItems($nameServers)
            ->selectKeys($this->nameServersKeys)
            ->selectKeyGroups($this->nameServersKeysGroups)
            ->mapAsciiServer()
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();

        if (empty($nameServers)) {
            $nameServers = $primaryFilter->toSelector()
                ->useMatchFirstOnly(true)
                ->selectKeys($this->nameServersKeys)
                ->selectKeyGroups($this->nameServersKeysGroups)
                ->mapAsciiServer()
                ->removeEmpty()
                ->removeDuplicates()
                ->getAll();
        }

        // Owner
        $owner = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->ownerSubsets)
            ->toSelector()
            ->selectKeys($this->ownerKeys)
            ->getFirst();

        if (empty($owner)) {
            $owner = $primaryFilter->toSelector()
                ->selectKeys($this->ownerKeys)
                ->getFirst();
        }

        if (!empty($owner)) {
            $owner = $rootFilter->cloneMe()
                ->setSubsetParams(['$id' => $owner])
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->contactSubsets)
                ->toSelector()
                ->selectKeys($this->contactOrgKeys)
                ->selectItems([ $owner ])
                ->removeEmpty()
                ->getFirst();
        }

        // Registrar
        $registrar = $primaryFilter->toSelector()
            ->useMatchFirstOnly(true)
            ->selectKeys($this->registrarKeys)
            ->getFirst();

        if (empty($registrar)) {
            $registrarFilter = $rootFilter->cloneMe()
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->registrarSubsets);

            $registrar = $registrarFilter->toSelector()
                ->selectKeys($this->registrarGroupKeys)
                ->getFirst();
        }
        if (empty($registrar) && !empty($registrarFilter)) {
            $registrar = $registrarFilter->filterHasHeader()
                ->toSelector()
                ->selectKeys([ 'name' ])
                ->getFirst();
        }
        if (empty($registrar)) {
            $registrar = $primaryFilter->toSelector()
                ->selectKeys($this->registrarKeys)
                ->getFirst();
        }

        $regFilter = $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->registrarReservedSubsets);

        $regId = $regFilter->toSelector()
            ->selectKeys($this->registrarReservedKeys)
            ->getFirst();

        if (!empty($regId) && (empty($registrar) || $regFilter->getFirstGroup() != $primaryFilter->getFirstGroup())) {
            $registrarOrg = $rootFilter->cloneMe()
                ->setSubsetParams(['$id' => $regId])
                ->useMatchFirstOnly(true)
                ->filterHasSubsetOf($this->contactSubsets)
                ->toSelector()
                ->selectKeys($this->contactOrgKeys)
                ->getFirst();

            $registrar = ($registrarOrg && $registrarOrg != $owner)
                ? $registrarOrg
                : $registrar;
        }

        // creationDate
        $creationDate = $primaryFilter->toSelector()
            ->selectKeys($this->creationDateKeys)
            ->mapUnixTime()
            ->getFirst();

        if (empty($creationDate)) {
            $creationDate = $rootFilter->cloneMe()
                ->useMatchFirstOnly(true)
                ->filterHasSubsetKeyOf($this->creationDateKeys)
                ->toSelector()
                ->selectKeys($this->creationDateKeys)
                ->mapUnixTime()
                ->getFirst();
        }

        // expirationDate
        $expirationDate = $primaryFilter->toSelector()
            ->selectKeys($this->expirationDateKeys)
            ->mapUnixTime()
            ->getFirst();

        if (empty($expirationDate)) {
            $expirationDate = $rootFilter->cloneMe()
                ->useMatchFirstOnly(true)
                ->filterHasSubsetKeyOf($this->expirationDateKeys)
                ->toSelector()
                ->selectKeys($this->expirationDateKeys)
                ->mapUnixTime()
                ->getFirst();
        }

        // whoisServer
        $whoisServer = $primaryFilter->toSelector()
            ->selectKeys($this->whoisServerKeys)
            ->mapAsciiServer()
            ->getFirst();

        $info = new DomainInfo($response, [
            "domainName" => $domain,
            "states" => $states,
            "nameServers" => $nameServers,
            "owner" => $owner,
            "registrar" => $registrar,
            "creationDate" => $creationDate,
            "expirationDate" => $expirationDate,
            "whoisServer" => $whoisServer,
        ]);
        return $info->isValuable($this->notRegisteredStatesDict) ? $info : null;
    }
}
