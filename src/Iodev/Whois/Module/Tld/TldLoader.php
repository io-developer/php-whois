<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Loader\LoaderInterface;
use Iodev\Whois\Tool\DomainTool;

class TldLoader
{
    /** @var TldServer[] */
    protected array $lastUsedServers = [];

    protected ?TldResponse $loadedResponse = null;
    protected ?TldInfo $loadedInfo = null;
    
    public function __construct(
        protected LoaderInterface $loader,
        protected DomainTool $domainTool,
    ) {}

    /**
     * @return TldServer[]
     */
    public function getLastUsedServers(): array
    {
        return $this->lastUsedServers;
    }

    /**
     * @param TldServer[] $servers
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain(string $domain, array $servers): TldLookupDomainResult
    {
        $this->lastUsedServers = [];
        $this->loadedResponse = null;
        $this->loadedInfo = null;

        foreach ($servers as $server) {
            $this->lastUsedServers[] = $server;

            $command = new TldLookupDomainCommand(
                $this->domainTool,
                new TldQueryBuilder(),
            );
            $command
                ->setLoader($this->loader)
                ->setDomain($domain)
                ->setHost($server->host)
                ->setQueryFormat($server->queryFormat)
                ->setRecurseLimit($server->centralized ? 0 : 1)
                ->setParser($server->parser)
                ->execute()
            ;
            if ($command->getResult() !== null && $command->getResult()->info) {
                break;
            }
        }

        $result = $command->getResult();

        if ($result->response === null && $result->info === null) {
            throw new WhoisException('No response');
        }

        return $result;
    }
}
