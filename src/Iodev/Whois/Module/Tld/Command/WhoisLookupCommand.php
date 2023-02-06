<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Command;

use Iodev\Whois\Error\ConnectionException;
use Iodev\Whois\Error\WhoisException;
use Iodev\Whois\Module\Tld\Dto\LookupInfo;
use Iodev\Whois\Module\Tld\Dto\LookupResponse;
use Iodev\Whois\Module\Tld\Dto\LookupResult;
use Iodev\Whois\Module\Tld\Whois\QueryBuilder;
use Iodev\Whois\Selection\GroupSelector;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Tool\ParserTool;
use Iodev\Whois\Transport\Request;
use Iodev\Whois\Transport\Transport;

class WhoisLookupCommand
{
    public const DEFAULT_HOST = 'whois.iana.org';
    public const DEFAULT_QUERY_FORMAT = "%s\r\n";

    protected Transport $transport;
    protected string $host = self::DEFAULT_HOST;
    protected string $domain;
    protected string $queryFormat = self::DEFAULT_QUERY_FORMAT;
    protected ?LookupResult $result = null;

    public function __construct(
        protected QueryBuilder $queryBuilder,
        protected DomainTool $domainTool,
        protected ParserTool $parserTool,
        protected DateTool $dateTool,
    ) {}

    public function setTransport(Transport $transport): static
    {
        $this->transport = $transport;
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

    public function getResult(): ?LookupResult
    {
        return $this->result;
    }

    public function clearResult(): static
    {
        $this->result = null;
        return $this;
    }

    public function execute(): static
    {
        $this->clearResult();
        $this->request();
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
            ->setOptionStrict(false)
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
        $info = $this->parseResponse($lookupResp);

        $this->result = new LookupResult($lookupResp, $info);
    }

    protected function createLookupResponse(): LookupResponse
    {
        return new LookupResponse();
    }

    protected function parseResponse(LookupResponse $resp): ?LookupInfo
    {
        $lines = $this->parserTool->splitLines($resp->getOutput());
        $data = $this->parserTool->linesToSimpleKV($lines);
        
        $sel = new GroupSelector($this->domainTool, $this->dateTool);
        $sel->setOneGroup($data);

        $domain = $sel->cloneMe()
            ->selectKeys(['domain'])
            ->map(fn($item) => mb_strtolower((string) $item))
            ->removeEmpty()
            ->getFirst()
        ;
        $domainAscii = $this->domainTool->toAscii($domain);
        $domainUnicode = $this->domainTool->toUnicode($domainAscii);

        return $this->createInfo()
            ->setResponse($resp)
            ->setParserType('')
            ->setDomain($domainAscii)
            ->setDomainUnicode($domainUnicode)
            ->setWhoisHost($sel->cloneMe()
                ->selectKeys(['whois'])
                ->map(fn($item) => mb_strtolower((string) $item))
                ->removeEmpty()
                ->getFirst()
            )
            ->setRegistrant($sel->cloneMe()
                ->selectKeys(['organisation'])
                ->removeEmpty()
                ->getFirst()
            )
            ->setStatuses($sel->cloneMe()
                ->selectKeys(['status'])
                ->map(fn($item) => mb_strtolower((string) $item))
                ->removeEmpty()
                ->getAll()
            )
            ->setCreatedTs($sel->cloneMe()
                ->selectKeys(['created'])
                ->mapUnixTime()
                ->removeEmpty()
                ->getFirst()
            )
            ->setUpdatedTs($sel->cloneMe()
                ->selectKeys(['changed'])
                ->mapUnixTime()
                ->removeEmpty()
                ->getFirst()
            )
            ->setExpiresTs(0)
            ->setNameServers([])
        ;
    }

    protected function createInfo(): LookupInfo
    {
        return new LookupInfo();
    }
}
