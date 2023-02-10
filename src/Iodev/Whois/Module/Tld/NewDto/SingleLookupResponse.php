<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewDto;

use \Iodev\Whois\Module\Tld\Dto\LookupInfo;
use \Iodev\Whois\Transport\Response as TransportResponse;

class SingleLookupResponse
{
    protected ?SingleLookupRequest $request = null;
    protected ?TransportResponse $transportResponse = null;
    protected ?LookupInfo $lookupInfo = null;
    protected bool $lookupInfoValuable = false;
    protected int $lookupInfoScore = 0;

    /** @var SingleLookupResponse[] */
    protected array $altResponses = [];

    protected ?SingleLookupResponse $childResponse = null;
    protected ?SingleLookupResponse $nextResponse = null;

    public function setRequest(SingleLookupRequest $req): static
    {
        $this->request = $req;
        return $this;
    }

    public function getRequest(): ?SingleLookupRequest
    {
        return $this->request;
    }

    public function setTransportResponse(TransportResponse $response): static
    {
        $this->transportResponse = $response;
        return $this;
    }

    public function getTransportResponse(): ?TransportResponse
    {
        return $this->transportResponse;
    }

    public function setLookupInfo(LookupInfo $info): static
    {
        $this->lookupInfo = $info;
        return $this;
    }

    public function getLookupInfo(): ?LookupInfo
    {
        return $this->lookupInfo;
    }

    public function setLookupInfoValuable(bool $val): static
    {
        $this->lookupInfoValuable = $val;
        return $this;
    }

    public function getLookupInfoValuable(): bool
    {
        return $this->lookupInfoValuable;
    }

    public function setLookupInfoScore(int $score): static
    {
        $this->lookupInfoScore = $score;
        return $this;
    }

    public function getLookupInfoScore(): int
    {
        return $this->lookupInfoScore;
    }

    public function hasError(): bool
    {
        return $this->transportResponse?->hasError() ?? false;
    }

    public function isValuable(): bool
    {
        return ($this->transportResponse?->isValid() ?? false) && $this->lookupInfoValuable;
    }

    /**
     * @param SingleLookupResponse[] $responses
     */
    public function setAltResponses(array $responses): static
    {
        $this->altResponses = [];
        foreach ($responses as $response) {
            $this->addAltResponse($response);
        }
        return $this;
    }

    public function addAltResponse(SingleLookupResponse $response): static
    {
        $this->altResponses[] = $response;
        return $this;
    }

    /**
     * @return SingleLookupResponse[]
     */
    public function getAltResponses(): array
    {
        return $this->altResponses;
    }

    public function setChildResponse(SingleLookupResponse $response): static
    {
        $this->childResponse = $response;
        return $this;
    }

    public function getChildResponse(): ?SingleLookupResponse
    {
        return $this->childResponse;
    }

    public function setNextResponse(SingleLookupResponse $response): static
    {
        $this->nextResponse = $response;
        return $this;
    }

    public function getNextResponse(): ?SingleLookupResponse
    {
        return $this->nextResponse;
    }
}
