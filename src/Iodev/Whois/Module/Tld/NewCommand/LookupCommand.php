<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewCommand;

use Iodev\Whois\Error\ConnectionException;
use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupRequest;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupResponse;
use Iodev\Whois\Module\Tld\NewDto\LookupRequest;
use Iodev\Whois\Module\Tld\NewDto\LookupResponse;
use Iodev\Whois\Module\Tld\Parsing\ParserProviderInterface;
use Iodev\Whois\Module\Tld\Whois\QueryBuilder;
use Iodev\Whois\Module\Tld\Whois\ServerProviderInterface;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Transport\Transport;
use Psr\Container\ContainerInterface;

class LookupCommand
{
    protected LookupRequest $request;
    protected ?LookupResponse $response = null;
    protected Transport $transport;
    protected ServerProviderInterface $serverProvider;
    protected ParserProviderInterface $parserProvider;
    protected int $recursionMax = 1;

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

    protected function executeResolvedIntermediate(
        WhoisServer $server,
        ?string $customWhoisHost = null,
        int $recursionDepth = 0,
    ): IntermediateLookupResponse {

        $this->response = null;

        $req = $this->buildItermediateRequest($server, $customWhoisHost);
        $startWhoisHost = $req->getWhoisHost();

        $resp = $this->executeIntermediate($req);

        if (!$resp->isValuable() && $this->request->getAltQueryingEnabled()) {
            $req = $this->buildItermediateRequest($server, $customWhoisHost)
                ->setUseAltQuery(true)
            ;
            $altResp = $this->executeIntermediate($req);
            $resp->addAltResponse($altResp);
        }

        $bestResp = $resp->resolveMostValuable();
        $bestWhoisHost = $bestResp->getLookupInfo()?->getWhoisHost() ?? null;
        if (
            $recursionDepth < $this->recursionMax
            && $bestResp->isValuable()
            && !empty($bestWhoisHost)
            && $bestWhoisHost != $startWhoisHost
            && !$server->getCentralized()
        ) {
            $childResp = $this->executeResolvedIntermediate($server, $bestWhoisHost, $recursionDepth + 1);
            $resp->setChildResponse($childResp);
        }

        return $resp;
    }

    protected function executeIntermediate(IntermediateLookupRequest $req): IntermediateLookupResponse
    {
        $cmd = $this->makeIntermediateCommand()
            ->setTransport($this->transport)
            ->setParser($req->getWhoisServer()->getParser())
            ->setRequest($req)
            ->execute()
        ;
        $resp = $cmd->getResponse();
        $cmd->flush();
        return $resp;
    }

    protected function buildItermediateRequest(WhoisServer $server, ?string $customWhoisHost = null): IntermediateLookupRequest
    {
        return $this->makeIntermediateRequest()
            ->setDomain($this->request->getDomain())
            ->setWhoisServer($server)
            ->setCustomWhoisHost($customWhoisHost ?? $this->request->getCustomHost())
        ;
    }

    protected function buildItermediateCommand(IntermediateLookupRequest $req): IntermediateLookupCommand
    {
        return $this->makeIntermediateCommand()
            ->setRequest($req)
            ->setTransport($this->transport)
        ;
    }

    protected function makeIntermediateRequest(): IntermediateLookupRequest
    {
        return $this->container->get(IntermediateLookupRequest::class);
    }

    protected function makeIntermediateCommand(): IntermediateLookupCommand
    {
        return $this->container->get(IntermediateLookupCommand::class);
    }

    protected function makeResponse(): LookupResponse
    {
        return $this->container->get(LookupResponse::class);
    }
}
