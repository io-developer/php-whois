<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parsing;

class BlockParserOpts extends CommonParserOpts
{
    public array $reservedDomainKeys = ['Reserved name'];

    public array $reservedDomainSubsets = [];

    public array $domainSubsets = [];

    public array $primarySubsets = [];

    public array $statesSubsets = [];

    public array $nameServersSubsets = [];

    public array $nameServersSparsedSubsets = [];

    public array $ownerSubsets = [];

    public array $registrarSubsets = [];

    public array $registrarReservedSubsets = [];

    public array $registrarReservedKeys = [];

    public array $contactSubsets = [];

    public array $contactOrgKeys = [];

    public array $registrarGroupKeys = [];

    public array $updatedDateExtraKeys = ['changed'];
}