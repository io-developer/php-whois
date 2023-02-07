<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewDto;

use \Iodev\Whois\Module\Tld\Dto\LookupInfo;
use Iodev\Whois\Traits\TagErrorContainerTrait;

class LookupResponse
{
    use TagErrorContainerTrait;

    protected ?LookupRequest $request = null;
    protected ?IntermediateLookupResponse $resultIntermediateResponse = null;
    protected ?IntermediateLookupResponse $rootIntermediateResponse = null;

    public function setRequest(LookupRequest $request): static
    {
        $this->request = $request;
        return $this;
    }

    public function getRequest(): ?LookupRequest
    {
        return $this->request;
    }
    public function setResultIntermediateResponse(IntermediateLookupResponse $response): static
    {
        $this->resultIntermediateResponse = $response;
        return $this;
    }

    public function getResultIntermediateResponse(): ?IntermediateLookupResponse
    {
        return $this->resultIntermediateResponse;
    }

    public function setRootIntermediateResponse(IntermediateLookupResponse $response): static
    {
        $this->rootIntermediateResponse = $response;
        return $this;
    }

    public function getRootIntermediateResponse(): ?IntermediateLookupResponse
    {
        return $this->rootIntermediateResponse;
    }

    public function getLookupInfo(): ?LookupInfo
    {
        return $this->resultIntermediateResponse?->getLookupInfo() ?? null;
    }

    public function isDomainBusy(): bool
    {
        return $this->getLookupInfo() !== null;
    }
}
