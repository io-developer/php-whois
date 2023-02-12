<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewDto;

use \Iodev\Whois\Module\Tld\Dto\LookupInfo;
use Iodev\Whois\Traits\TagErrorContainerTrait;

class LookupResponse
{
    use TagErrorContainerTrait;

    protected ?LookupRequestData $requestData = null;
    protected ?SingleLookupResponse $resultSingleResponse = null;
    protected ?SingleLookupResponse $rootSingleResponse = null;

    public function setRequestData(LookupRequestData $requestData): static
    {
        $this->requestData = $requestData;
        return $this;
    }

    public function getRequestData(): ?LookupRequestData
    {
        return $this->requestData;
    }
    public function setResultSingleResponse(SingleLookupResponse $response): static
    {
        $this->resultSingleResponse = $response;
        return $this;
    }

    public function getResultSingleResponse(): ?SingleLookupResponse
    {
        return $this->resultSingleResponse;
    }

    public function setRootSingleResponse(SingleLookupResponse $response): static
    {
        $this->rootSingleResponse = $response;
        return $this;
    }

    public function getRootSingleResponse(): ?SingleLookupResponse
    {
        return $this->rootSingleResponse;
    }

    public function getLookupInfo(): ?LookupInfo
    {
        return $this->resultSingleResponse?->getLookupInfo() ?? null;
    }

    public function isDomainBusy(): bool
    {
        return $this->getLookupInfo() !== null;
    }
}
