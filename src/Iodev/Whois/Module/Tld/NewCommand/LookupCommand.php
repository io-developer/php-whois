<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewCommand;

use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Module\Tld\NewDto\SingleLookupRequestData;
use Iodev\Whois\Module\Tld\NewDto\SingleLookupResponse;
use Iodev\Whois\Module\Tld\NewDto\LookupRequestData;
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

    protected ?LookupRequestData $requestData = null;
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

    public function setRequestData(LookupRequestData $requestData): static
    {
        $this->requestData = $requestData;
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
        $this->requestData = null;
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
        $this->response = $this->makeResponse()->setRequestData($this->requestData);

        /** @var SingleLookupResponse */
        $root = null;

        /** @var SingleLookupResponse */
        $best = null;

        /** @var SingleLookupResponse */
        $prevRoot = null;

        /** @var SingleLookupResponse */
        $nextRoot = null;

        /** @var SingleLookupResponse */
        $nextBest = null;

        foreach ($this->requestData->getWhoisServers() as $server) {
            $prevRoot = $nextRoot;
            [$nextRoot, $nextBest] = $this->executeResolvedSingle($server);

            if ($root === null) {
                $root = $nextRoot;
                $best = $nextBest;
            } else {
                $prevRoot->setNextResponse($nextRoot);
                $best = $this->mostValuableLookupResolver->resolveSingleVariants([
                    $best,
                    $nextBest,
                ]);
            }

            if (!$this->resolveNextWhoisNeeded($best)) {
                break;
            }
        }

        $this->response
            ->setRootSingleResponse($root)
            ->setResultSingleResponse($best)
        ;
        return $this;
    }

    protected function executeResolvedSingle(
        WhoisServer $server,
        ?string $customWhoisHost = null,
        int $recursionDepth = 0,
    ): array {

        $reqData = $this->resolveSingleRequestData($server, $customWhoisHost);
        $resp = $this->executeSingle($reqData);

        $altReqData = $this->resolveAltSingleRequestData($resp);
        if ($altReqData !== null) {
            $resp->addAltResponse($this->executeSingle($altReqData));
        }

        $bestResp = $this->mostValuableLookupResolver->resolveSingleTree($resp);

        $childWhoisHost = $this->resolveChildWhoisHost($bestResp, $recursionDepth);
        if ($childWhoisHost !== null) {
            [$childResp, $childBestResp] = $this->executeResolvedSingle(
                $server,
                $childWhoisHost,
                $recursionDepth + 1,
            );
            $resp->setChildResponse($childResp);

            $bestResp = $this->mostValuableLookupResolver->resolveSingleVariants([
                $bestResp,
                $childBestResp,
            ]);
        }

        return [$resp, $bestResp];
    }

    protected function resolveNextWhoisNeeded(SingleLookupResponse $best): bool
    {
        return !$best->isValuable();
    }

    protected function resolveSingleRequestData(WhoisServer $server, ?string $customWhoisHost = null): SingleLookupRequestData
    {
        $customWhoisHost = $customWhoisHost ?? $this->requestData->getCustomWhoisHost();
        if (!empty($customWhoisHost)) {
            $server = clone $server;
            $server->setHost($customWhoisHost);
        }
        return $this->makeSingleRequestData()
            ->setDomain($this->requestData->getDomain())
            ->setTransportTimeout($this->requestData->getTransportTimeout())
            ->setWhoisServer($server)
        ;
    }

    protected function resolveAltSingleRequestData(SingleLookupResponse $main): ?SingleLookupRequestData
    {
        if (!$this->requestData->getAltQueryingEnabled()) {
            return null;
        }
        if ($main->isValuable()) {
            return null;
        }
        $reqData = $main->getRequestData();
        if ($reqData->getUseAltQuery()) {
            return null;
        }

        $reqData = clone $reqData;
        return $reqData->setUseAltQuery(true);
    }

    protected function resolveChildWhoisHost(SingleLookupResponse $resp, int $recursionDepth): ?string
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
        $reqData = $resp->getRequestData();
        $server = $reqData->getWhoisServer();
        if ($server->getCentralized()) {
            return null;
        }
        $infoWhoisHost = $info->getWhoisHost();
        if (empty($infoWhoisHost) || $infoWhoisHost == $server->getHost()) {
            return null;
        }
        return $infoWhoisHost;
    }

    protected function executeSingle(SingleLookupRequestData $reqData): SingleLookupResponse
    {
        $cmd = $this->makeSingleCommand()
            ->setTransport($this->transport)
            ->setParser($reqData->getWhoisServer()->getParser())
            ->setRequestData($reqData)
            ->execute()
        ;
        $resp = $cmd->getResponse();
        $cmd->flush(true);
        return $resp;
    }

    protected function makeSingleRequestData(): SingleLookupRequestData
    {
        return $this->container->get(SingleLookupRequest::class);
    }

    protected function makeSingleCommand(): SingleLookupCommand
    {
        return $this->container->get(SingleLookupCommand::class);
    }

    protected function makeResponse(): LookupResponse
    {
        return $this->container->get(LookupResponse::class);
    }
}
