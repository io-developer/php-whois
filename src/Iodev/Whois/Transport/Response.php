<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

use Iodev\Whois\Transport\Error\Error;

class Response
{
    protected ?Request $request = null;
    protected ?string $output = null;
    protected array $errors = [];
    protected string $transportClass = '';
    protected string $loaderClass = '';
    protected array $middlewareClasses = [];
    protected array $processorClasses = [];
    protected array $validatorClasses = [];


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
        return $this->output !== null && !$this->hasErrors();
    }


    /**
     * @param Error[] $errors
     */
    public function setErrors(array $errors): static
    {
        $this->errors = [];
        foreach ($errors as $error) {
            $this->addError($error);
        }
        return $this;
    }

    public function addError(Error $err): static
    {
        $this->errors[] = $err;
        return $this;
    }

    /**
     * @return Error[]
     */
    public function getErrors(?string $type = null): array
    {
        if ($type === null) {
            return $this->errors;
        }
        return array_values(array_filter(
            $this->getErrors(),
            function (Error $err) use ($type) {
                return $err->type === $type;
            }
        ));
    }

    public function hasErrors(): bool
    {
        return count($this->getErrors()) > 0;
    }

    public function getSummaryErrorMessage(): string
    {
        if ($this->isValid()) {
            return '';
        }
        if (!$this->hasErrors()) {
            return 'Invalid WHOIS response';
        }
        $lines = array_map(
            fn(Error $err) => $err->getSummaryMessage(),
            $this->getErrors(),
        );
        return implode("\n", $lines);
    }


    public function setTransportClass(string $className): static
    {
        $this->transportClass = $className;
        return $this;
    }

    public function getTransportClass(): string
    {
        return $this->transportClass;
    }


    public function setLoaderClass(string $className): static
    {
        $this->loaderClass = $className;
        return $this;
    }

    public function getLoaderClass(): string
    {
        return $this->loaderClass;
    }

    
    /**
     * @param string[] $classNames
     */
    public function setMiddlewareClasses(array $classNames): static
    {
        $this->middlewareClasses = array_map(fn($item) => (string)$item, $classNames);
        return $this;
    }

    /**
     * @return string[]
     */
    public function getMiddlewareClasses(): array
    {
        return $this->middlewareClasses;
    }


    /**
     * @param string[] $classNames
     */
    public function setProcessorClasses(array $classNames): static
    {
        $this->processorClasses = array_map(fn($item) => (string)$item, $classNames);
        return $this;
    }

    /**
     * @return string[]
     */
    public function getProcessorClasses(): array
    {
        return $this->processorClasses;
    }


    /**
     * @param string[] $classNames
     */
    public function setValidatorClasses(array $classNames): static
    {
        $this->validatorClasses = array_map(fn($item) => (string)$item, $classNames);
        return $this;
    }

    /**
     * @return string[]
     */
    public function getValidatorClasses(): array
    {
        return $this->validatorClasses;
    }
}
