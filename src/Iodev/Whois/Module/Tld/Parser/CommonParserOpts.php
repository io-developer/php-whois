<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parser;

class CommonParserOpts
{
    public string $headerKey = 'HEADER';

    public bool $isFlat = false;

    public array $domainKeys = ['domain name'];

    public array $whoisServerKeys = ['whois server'];

    public array $nameServersKeys = ['name server'];

    public array $nameServersKeysGroups = [
        ['ns 1', 'ns 2', 'ns 3', 'ns 4'],
    ];

    public array $dnssecKeys = ['dnssec'];

    public array $creationDateKeys = ['creation date'];

    public array $expirationDateKeys = ['expiration date'];

    public array $updatedDateKeys = ['updated date'];

    public array $ownerKeys = ['owner-organization'];

    public array $registrarKeys = ['registrar'];

    public array $statesKeys = ['domain status'];

    public array $notRegisteredStatesDict = ['not registered' => 1];

    public array $emptyValuesDict = [
        '' => 1,
        'not.defined.' => 1,
    ];
}