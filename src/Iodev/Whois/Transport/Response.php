<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

class Response
{
    protected readonly Request $request;
    protected readonly string $output;
    protected readonly array $errors;
    protected readonly string $loaderClass;
    protected readonly array $processorClasses;
    protected readonly array $validatorClasses;


    public function setRequest(Request $req): static
    {
        $this->request = $req;
        return $this;
    }

    public function getRequest(): ?Request
    {
        return $this->request ?? null;
    }


    public function setOutput(string $output): static
    {
        $this->output = $output;
        return $this;
    }

    public function getOutput(): string
    {
        return $this->output ?? '';
    }


    /**
     * @param Error[] $errors
     */
    public function setErrors(array $errors): static
    {
        $this->errors = array_map(fn(Error $err) => $err, $errors);
        return $this;
    }

    /**
     * @return Error[]
     */
    public function getErrors(): array
    {
        return $this->errors ?? [];
    }

    public function hasErrors(): bool
    {
        return count($this->getErrors()) > 0;
    }

    public function isValid(): bool
    {
        return !$this->hasErrors();
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

    /**
     * @return Error[]
     */
    public function getErrorsByType(string $type): array
    {
        return array_values(array_filter(
            $this->getErrors(),
            function (Error $err) use ($type) {
                return $err->type === $type;
            }
        ));
    }


    public function setLoaderClass(string $loader): static
    {
        $this->loaderClass = $loader;
        return $this;
    }

    public function getLoaderClass(): string
    {
        return $this->loaderClass ?? '';
    }


    /**
     * @param string[] $processors
     */
    public function setProcessorClasses(array $processors): static
    {
        $this->processorClasses = array_map(fn($item) => (string)$item, $processors);
        return $this;
    }

    /**
     * @return string[]
     */
    public function getProcessorClasses(): array
    {
        return $this->processorClasses ?? [];
    }


    /**
     * @param string[] $validators
     */
    public function setValidatorClasses(array $validators): static
    {
        $this->validatorClasses = array_map(fn($item) => (string)$item, $validators);
        return $this;
    }

    /**
     * @return string[]
     */
    public function getValidatorClasses(): array
    {
        return $this->validatorClasses ?? [];
    }
}
