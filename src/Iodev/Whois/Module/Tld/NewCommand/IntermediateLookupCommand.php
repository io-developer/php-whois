<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewCommand;

use Iodev\Whois\Error\ConnectionException;
use Iodev\Whois\Error\WhoisException;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupResponse;
use Iodev\Whois\Module\Tld\Parsing\ParserInterface;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupRequest;
use Iodev\Whois\Module\Tld\Whois\QueryBuilder;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Transport\Request;
use Iodev\Whois\Transport\Transport;

class IntermediateLookupCommand
{
    protected Transport $transport;
    protected IntermediateLookupRequest $request;
    protected IntermediateLookupResponse $response;

    protected ?LookupCommand $childCommand = null;
    protected ?LookupResult $result = null;
    protected ?LookupResult $lastResult = null;

    /** @var LookupResult[] */
    protected array $lastResults = [];


    public function __construct(
        protected QueryBuilder $queryBuilder,
        protected DomainTool $domainTool,
    ) {}


    public function setRequest(IntermediateLookupRequest $req): static
    {
        $this->request = $req;
        return $this;
    }

    public function setTransport(Transport $transport): static
    {
        $this->transport = $transport;
        return $this;
    }

    public function getResponse(): ?IntermediateLookupResponse
    {
        return $this->response;
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
            && !empty($info->getWhoisHost())
            && $info->getWhoisHost() != $this->host
        ) {
            $this->childCommand = (clone $this);
            $this->childCommand
                ->clearResult()
                ->setRecursionLimit($this->recursionLimit - 1)
                ->setHost($info->getWhoisHost())
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
        $req = (new Request())
            ->setHost($this->host)
            ->setQuery($queryStr)
        ;
        $resp = $this->transport
            ->sendRequest($req)
            ->getResponse()
        ;
        if (!$resp->isValid()) {
            throw new WhoisException($resp->getSummaryErrorMessage());
        }
        $lookupResp = $this->createLookupResponse()
            ->setDomain($domain)
            ->setHost($req->getHost())
            ->setQuery($req->getQuery())
            ->setOutput($resp->getOutput())
        ;
        $info = $this->parser->parseResponse($lookupResp);

        $this->lastResult = new LookupResult($lookupResp, $info);
        $this->lastResults[] = $this->lastResult;
    }

    protected function createLookupResponse(): LookupResponse
    {
        return new LookupResponse();
    }
}
