<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Loader\LoaderInterface;
use Iodev\Whois\Tool\DomainTool;

class TldLookupDomainCommand
{
    protected LoaderInterface $loader;
    protected string $host;
    protected string $domain;
    protected string $queryFormat;
    protected TldParser $parser;
    protected int $recursionLimit = 0;
    protected bool $altQueryEnabled = true;

    protected ?TldLookupDomainCommand $childCommand = null;
    protected ?TldLookupDomainResult $result = null;
    protected ?TldLookupDomainResult $lastResult = null;

    /** @var TldLookupDomainResult[] */
    protected array $lastResults = [];


    public function __construct(
        protected DomainTool $domainTool,
        protected TldQueryBuilder $queryBuilder,
    ) {}


    public function setLoader(LoaderInterface $loader): static
    {
        $this->loader = $loader;
        return $this;
    }

    public function setHost(string $host): static
    {
        $this->host = $host;
        return $this;
    }

    public function setDomain(string $domain): static
    {
        $this->domain = $domain;
        return $this;
    }

    public function setQueryFormat(string $format): static
    {
        $this->queryFormat = $format;
        return $this;
    }

    public function setParser(TldParser $parser): static
    {
        $this->parser = $parser;
        return $this;
    }

    public function setRecursionLimit(int $limit): static
    {
        $this->recursionLimit = $limit;
        return $this;
    }

    public function setAltQueryEnabled(bool $yes): static
    {
        $this->altQueryEnabled = $yes;
        return $this;
    }

    public function getResult(): ?TldLookupDomainResult
    {
        return $this->result;
    }

    public function getLastResult(): ?TldLookupDomainResult
    {
        return $this->lastResult;
    }

    /**
     * @return TldLookupDomainResult[]
     */
    public function getLastResults(): array
    {
        return $this->lastResults;
    }

    public function getChildCommand(): ?TldLookupDomainCommand
    {
        return $this->childCommand;
    }

    protected function resolveResult(): ?TldLookupDomainResult
    {
        if ($this->childCommand !== null) {
            $childResult = $this->childCommand->getResult();
            if ($childResult !== null && $childResult->info !== null) {
                $this->result = $childResult;
                return $this->result;
            }
        }
        $this->result = $this->lastResult;
        foreach ($this->lastResults as $result) {
            if ($result->response === null && $result->info === null) {
                continue;
            }
            $this->result = $result;
        }
        return $this->result;
    }


    public function clearResult(): static
    {
        $this->result = null;
        $this->lastResult = null;
        $this->lastResults = [];

        $this->childCommand = null;

        return $this;
    }

    public function execute(): static
    {
        $this->clearResult();

        $lastError = null;
        try {
            $this->queryBuilder->setOptionStrict(false);
            $this->request();
        } catch (ConnectionException $err) {
            $lastError = $err;
        }

        if ($this->lastResult->info === null && $this->altQueryEnabled) {
            $this->queryBuilder->setOptionStrict(true);
            $this->request();
        }

        $info = $this->resolveResult()->info;

        if ($info === null && $lastError !== null) {
            throw $lastError;
        }

        if (
            $this->recursionLimit > 0
            && $info !== null
            && !empty($info->whoisServer)
            && $info->whoisServer != $this->host
        ) {
            $this->childCommand = (clone $this);
            $this->childCommand
                ->clearResult()
                ->setRecursionLimit($this->recursionLimit - 1)
                ->setHost($info->whoisServer)
                ->execute()
            ;
            $this->resolveResult();
        }

        return $this;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    protected function request()
    {
        $domain = $this->domainTool->toAscii($this->domain);

        $queryStr = $this->queryBuilder
            ->setFormat($this->queryFormat)
            ->setQueryText($domain)
            ->toString()
        ;
        $text = $this->loader->loadText($this->host, $queryStr);

        $resp = new TldResponse($domain, $this->host, $queryStr, $text);
        $info = $this->parser->parseResponse($resp);

        $this->lastResult = new TldLookupDomainResult($resp, $info);
        $this->lastResults[] = $this->lastResult;
    }
}
