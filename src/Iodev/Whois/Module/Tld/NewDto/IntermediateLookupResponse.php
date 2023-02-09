<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\NewDto;

use \Iodev\Whois\Module\Tld\Dto\LookupInfo;
use \Iodev\Whois\Transport\Response as TransportResponse;

class IntermediateLookupResponse
{
    protected ?IntermediateLookupRequest $request = null;
    protected ?TransportResponse $transportResponse = null;
    protected ?LookupInfo $lookupInfo = null;
    protected bool $lookupInfoValuable = false;
    protected int $lookupInfoScore = 0;

    /** @var IntermediateLookupResponse[] */
    protected array $altResponses = [];

    protected ?IntermediateLookupResponse $childResponse = null;
    protected ?IntermediateLookupResponse $nextResponse = null;

    public function setRequest(IntermediateLookupRequest $req): static
    {
        $this->request = $req;
        return $this;
    }

    public function getRequest(): ?IntermediateLookupRequest
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
     * @param IntermediateLookupResponse[] $responses
     */
    public function setAltResponses(array $responses): static
    {
        $this->altResponses = [];
        foreach ($responses as $response) {
            $this->addAltResponse($response);
        }
        return $this;
    }

    public function addAltResponse(IntermediateLookupResponse $response): static
    {
        $this->altResponses[] = $response;
        return $this;
    }

    /**
     * @return IntermediateLookupResponse[]
     */
    public function getAltResponses(): array
    {
        return $this->altResponses;
    }

    public function setChildResponse(IntermediateLookupResponse $response): static
    {
        $this->childResponse = $response;
        return $this;
    }

    public function getChildResponse(): ?IntermediateLookupResponse
    {
        return $this->childResponse;
    }

    public function setNextResponse(IntermediateLookupResponse $response): static
    {
        $this->nextResponse = $response;
        return $this;
    }

    public function getNextResponse(): ?IntermediateLookupResponse
    {
        return $this->nextResponse;
    }
}
