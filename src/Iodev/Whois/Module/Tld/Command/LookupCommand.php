<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Command;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Loader\LoaderInterface;
use Iodev\Whois\Module\Tld\Dto\LookupResponse;
use Iodev\Whois\Module\Tld\Dto\LookupResult;
use Iodev\Whois\Module\Tld\Parsing\ParserInterface;
use Iodev\Whois\Module\Tld\Whois\QueryBuilder;
use Iodev\Whois\Tool\DomainTool;

class LookupCommand
{
    protected LoaderInterface $loader;
    protected string $host;
    protected string $domain;
    protected string $queryFormat;
    protected ParserInterface $parser;
    protected int $recursionLimit = 0;
    protected bool $altQueryEnabled = true;

    protected ?LookupCommand $childCommand = null;
    protected ?LookupResult $result = null;
    protected ?LookupResult $lastResult = null;

    /** @var LookupResult[] */
    protected array $lastResults = [];


    public function __construct(
        protected QueryBuilder $queryBuilder,
        protected DomainTool $domainTool,
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

    public function setParser(ParserInterface $parser): static
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

    public function getResult(): ?LookupResult
    {
        return $this->result;
    }

    public function getLastResult(): ?LookupResult
    {
        return $this->lastResult;
    }

    /**
     * @return LookupResult[]
     */
    public function getLastResults(): array
    {
        return $this->lastResults;
    }

    public function getChildCommand(): ?LookupCommand
    {
        return $this->childCommand;
    }

    protected function resolveResult(): ?LookupResult
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

        $resp = $this->createResponse()
            ->setDomain($domain)
            ->setHost($this->host)
            ->setQuery($queryStr)
            ->setOutput($text)
        ;
        $info = $this->parser->parseResponse($resp);

        $this->lastResult = new LookupResult($resp, $info);
        $this->lastResults[] = $this->lastResult;
    }

    protected function createResponse(): LookupResponse
    {
        return new LookupResponse();
    }
}
