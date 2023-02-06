<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

use \Iodev\Whois\Traits\TagErrorContainerTrait;

class Response
{
    use TagErrorContainerTrait;

    protected ?Request $request = null;
    protected ?string $output = null;
    protected string $usedTransportClass = '';
    protected string $usedLoaderClass = '';
    protected array $usedMiddlewareClasses = [];

    public function setRequest(Request $req): static
    {
        $this->request = $req;
        return $this;
    }

    public function getRequest(): ?Request
    {
        return $this->request;
    }

    public function setOutput(?string $output): static
    {
        $this->output = $output;
        return $this;
    }

    public function getOutput(): ?string
    {
        return $this->output;
    }

    public function isValid(): bool
    {
        return $this->output !== null && !$this->hasError();
    }

    public function setUsedTransportClass(string $className): static
    {
        $this->usedTransportClass = $className;
        return $this;
    }

    public function getUsedTransportClass(): string
    {
        return $this->usedTransportClass;
    }

    public function setUsedLoaderClass(string $className): static
    {
        $this->usedLoaderClass = $className;
        return $this;
    }

    public function getUsedLoaderClass(): string
    {
        return $this->usedLoaderClass;
    }
    
    /**
     * @param string[] $classNames
     */
    public function setUsedMiddlewareClasses(array $classNames): static
    {
        $this->usedMiddlewareClasses = array_map(fn($item) => (string)$item, $classNames);
        return $this;
    }

    /**
     * @return string[]
     */
    public function getUsedMiddlewareClasses(): array
    {
        return $this->usedMiddlewareClasses;
    }
}
