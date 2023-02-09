<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewCommand;

use Iodev\Whois\Error\WhoisException;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupResponse;
use Iodev\Whois\Module\Tld\Parsing\ParserInterface;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupRequest;
use Iodev\Whois\Module\Tld\Tool\LookupInfoScoreCalculator;
use Iodev\Whois\Module\Tld\Whois\QueryBuilder;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Transport\Request;
use Iodev\Whois\Transport\Transport;
use Psr\Container\ContainerInterface;

class IntermediateLookupCommand
{
    protected ?IntermediateLookupRequest $request = null;
    protected ?IntermediateLookupResponse $response = null;
    protected ?Transport $transport = null;
    protected ?ParserInterface $parser = null;
    
    public function __construct(
        protected ContainerInterface $container,
        protected DomainTool $domainTool,
        protected LookupInfoScoreCalculator $scoreCalculator,
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

    public function setParser(ParserInterface $parser): static
    {
        $this->parser = $parser;
        return $this;
    }

    public function getResponse(): ?IntermediateLookupResponse
    {
        return $this->response;
    }

    public function flush(bool $allParams = false): static
    {
        $this->request = null;
        $this->response = null;

        if ($allParams) {
            $this->transport = null;
            $this->parser = null;
        }

        return $this;
    }

    public function execute(): static
    {
        $req = $this->request;

        $this->response = $this->makeResponse();
        $this->response->setRequest($req);

        $domain = $this->domainTool->toAscii($req->getDomain());

        $qb = $this->makeQueryBuilder()
            ->setFormat($req->getWhoisServer()->getQueryFormat())
            ->setQueryText($domain)
            ->setOptionStrict($req->getUseAltQuery())
        ;
        $query = $qb->toString();

        $transportReq = (new Request())
            ->setHost($req->getWhoisServer()->getHost())
            ->setPort($req->getWhoisServer()->getPort())
            ->setTimeout($req->getTransportTimeout())
            ->setQuery($query)
        ;
        $transportResp = $this->transport
            ->sendRequest($transportReq)
            ->getResponse()
        ;
        $this->response->setTransportResponse($transportResp);

        if (!$transportResp->isValid()) {
            throw new WhoisException($transportResp->getSummaryErrorMessage());
        }

        $info = $this->parser->parseResponse($this->createOldLookupResponse());
        $this->response->setLookupInfo($info);

        $score = $this->scoreCalculator->calcRank($info);
        $this->response->setLookupInfoScore($score);

        return $this;
    }

    protected function createOldLookupResponse(): \Iodev\Whois\Module\Tld\Dto\LookupResponse
    {
        return (new \Iodev\Whois\Module\Tld\Dto\LookupResponse())
            ->setDomain($this->request->getDomain())
            ->setHost($this->response->getTransportResponse()->getRequest()->getHost())
            ->setQuery($this->response->getTransportResponse()->getRequest()->getQuery())
            ->setOutput($this->response->getTransportResponse()->getOutput())
        ;
    }

    protected function makeQueryBuilder(): QueryBuilder
    {
        return $this->container->get(QueryBuilder::class);
    }

    protected function makeResponse(): IntermediateLookupResponse
    {
        return $this->container->get(IntermediateLookupResponse::class);
    }
}
