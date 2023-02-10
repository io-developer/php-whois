<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewCommand;

use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupRequest;
use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupResponse;
use Iodev\Whois\Module\Tld\NewDto\LookupRequest;
use Iodev\Whois\Module\Tld\NewDto\LookupResponse;
use Iodev\Whois\Module\Tld\Parsing\ParserProviderInterface;
use Iodev\Whois\Module\Tld\Tool\MostValuableLookupResolver;
use Iodev\Whois\Module\Tld\Whois\QueryBuilder;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Transport\Transport;
use Psr\Container\ContainerInterface;

class LookupCommand
{
    public const DEFAULT_RECURSION_MAX = 1;

    protected ?LookupRequest $request = null;
    protected ?LookupResponse $response = null;
    protected ?Transport $transport = null;
    protected ?ParserProviderInterface $parserProvider = null;
    protected int $recursionMax = self::DEFAULT_RECURSION_MAX;

    public function __construct(
        protected ContainerInterface $container,
        protected QueryBuilder $queryBuilder,
        protected DomainTool $domainTool,
        protected MostValuableLookupResolver $mostValuableLookupResolver,
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

    public function setParserProvider(ParserProviderInterface $parserProvider): static
    {
        $this->parserProvider = $parserProvider;
        return $this;
    }

    public function getResponse(): ?LookupResponse
    {
        return $this->response;
    }

    public function flush(bool $allParams = false): static
    {
        $this->request = null;
        $this->response = null;

        if ($allParams) {
            $this->transport = null;
            $this->parserProvider = null;
            $this->recursionMax = static::DEFAULT_RECURSION_MAX;
        }

        return $this;
    }

    public function execute(): static
    {
        $this->response = $this->makeResponse()->setRequest($this->request);

        /** @var IntermediateLookupResponse */
        $root = null;

        /** @var IntermediateLookupResponse */
        $best = null;

        /** @var IntermediateLookupResponse */
        $prevRoot = null;

        /** @var IntermediateLookupResponse */
        $nextRoot = null;

        /** @var IntermediateLookupResponse */
        $nextBest = null;

        foreach ($this->request->getWhoisServers() as $server) {
            $prevRoot = $nextRoot;
            [$nextRoot, $nextBest] = $this->executeResolvedIntermediate($server);

            if ($root === null) {
                $root = $nextRoot;
                $best = $nextBest;
            } else {
                $prevRoot->setNextResponse($nextRoot);
                $best = $this->mostValuableLookupResolver->resolveIntermediateVariants([
                    $best,
                    $nextBest,
                ]);
            }

            if (!$this->resolveNextWhoisNeeded($best)) {
                break;
            }
        }

        $this->response
            ->setRootIntermediateResponse($root)
            ->setResultIntermediateResponse($best)
        ;
        return $this;
    }

    protected function executeResolvedIntermediate(
        WhoisServer $server,
        ?string $customWhoisHost = null,
        int $recursionDepth = 0,
    ): array {

        $req = $this->resolveSingleRequest($server, $customWhoisHost);
        $resp = $this->executeIntermediate($req);

        $altReq = $this->resolveAltSingleRequest($resp);
        if ($altReq !== null) {
            $resp->addAltResponse($this->executeIntermediate($altReq));
        }

        $bestResp = $this->mostValuableLookupResolver->resolveIntermediateTree($resp);

        $childWhoisHost = $this->resolveChildWhoisHost($bestResp, $recursionDepth);
        if ($childWhoisHost !== null) {
            [$childResp, $childBestResp] = $this->executeResolvedIntermediate(
                $server,
                $childWhoisHost,
                $recursionDepth + 1,
            );
            $resp->setChildResponse($childResp);

            $bestResp = $this->mostValuableLookupResolver->resolveIntermediateVariants([
                $bestResp,
                $childBestResp,
            ]);
        }

        return [$resp, $bestResp];
    }

    protected function resolveNextWhoisNeeded(IntermediateLookupResponse $best): bool
    {
        return !$best->isValuable();
    }

    protected function resolveSingleRequest(WhoisServer $server, ?string $customWhoisHost = null): IntermediateLookupRequest
    {
        $customWhoisHost = $customWhoisHost ?? $this->request->getCustomWhoisHost();
        if (!empty($customWhoisHost)) {
            $server = clone $server;
            $server->setHost($customWhoisHost);
        }
        return $this->makeIntermediateRequest()
            ->setDomain($this->request->getDomain())
            ->setTransportTimeout($this->request->getTransportTimeout())
            ->setWhoisServer($server)
        ;
    }

    protected function resolveAltSingleRequest(IntermediateLookupResponse $main): ?IntermediateLookupRequest
    {
        if (!$this->request->getAltQueryingEnabled()) {
            return null;
        }
        if ($main->isValuable()) {
            return null;
        }
        $req = $main->getRequest();
        if ($req->getUseAltQuery()) {
            return null;
        }

        $req = clone $req;
        return $req->setUseAltQuery(true);
    }

    protected function resolveChildWhoisHost(IntermediateLookupResponse $resp, int $recursionDepth): ?string
    {
        if ($recursionDepth >= $this->recursionMax) {
            return null;
        }
        if (!$resp->isValuable()) {
            return null;
        }
        $info = $resp->getLookupInfo();
        if ($info === null) {
            return null;
        }
        $req = $resp->getRequest();
        $server = $req->getWhoisServer();
        if ($server->getCentralized()) {
            return null;
        }
        $infoWhoisHost = $info->getWhoisHost();
        if (empty($infoWhoisHost) || $infoWhoisHost == $server->getHost()) {
            return null;
        }
        return $infoWhoisHost;
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
        $cmd->flush(true);
        return $resp;
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
