<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewCommand;

use Iodev\Whois\Error\ConnectionException;
use Iodev\Whois\Error\WhoisException;
use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupRequest;
use Iodev\Whois\Module\Tld\NewDto\LookupRequest;
use Iodev\Whois\Module\Tld\NewDto\LookupResponse;
use Iodev\Whois\Module\Tld\Parsing\ParserProviderInterface;
use Iodev\Whois\Module\Tld\Whois\QueryBuilder;
use Iodev\Whois\Module\Tld\Whois\ServerProviderInterface;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Transport\Request;
use Iodev\Whois\Transport\Transport;
use Psr\Container\ContainerInterface;

class LookupCommand
{
    protected LookupRequest $request;
    protected ?LookupResponse $response = null;
    protected Transport $transport;
    protected ServerProviderInterface $serverProvider;
    protected ParserProviderInterface $parserProvider;

    public function __construct(
        protected ContainerInterface $container,
        protected QueryBuilder $queryBuilder,
        protected DomainTool $domainTool,
    ) {}

    public function setLookupRequest(LookupRequest $req): static
    {
        $this->request = $req;
        return $this;
    }

    public function setTransport(Transport $transport): static
    {
        $this->transport = $transport;
        return $this;
    }

    public function setServerProvider(ServerProviderInterface $serverProvider): static
    {
        $this->serverProvider = $serverProvider;
        return $this;
    }

    public function setParserProvider(ParserProviderInterface $parserProvider): static
    {
        $this->parserProvider = $parserProvider;
        return $this;
    }

    public function getResponse(): ?LookupResponse
    {
        return $this->response;
    }

    public function executeOne(WhoisServer $server): static
    {
        $this->response = null;

        $req = $this->buildItermediateRequest($server);
        $cmd = $this->buildItermediateCommand($req);
        $cmd->execute();
        $resp = $cmd->getResponse();

        $resp->getTransportResponse()->hasError();
        $resp->getLookupInfo();

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

    protected function buildItermediateRequest(WhoisServer $server): IntermediateLookupRequest
    {
        return $this->createIntermediateRequest()
            ->setDomain($this->request->getDomain())
            ->setWhoisServer($server)
        ;
    }

    protected function buildItermediateCommand(IntermediateLookupRequest $req): IntermediateLookupCommand
    {
        return $this->createIntermediateCommand()
            ->setRequest($req)
            ->setTransport($this->transport)
        ;
    }

    protected function createIntermediateRequest(): IntermediateLookupRequest
    {
        return $this->container->get(IntermediateLookupRequest::class);
    }

    protected function createIntermediateCommand(): IntermediateLookupCommand
    {
        return $this->container->get(IntermediateLookupCommand::class);
    }

    protected function createResponse(): LookupResponse
    {
        return $this->container->get(LookupResponse::class);
    }
}
