<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

use Iodev\Whois\Transport\Error\Error;
use Iodev\Whois\Transport\Error\TransportError;
use Throwable;

class Response
{
    protected ?Request $request = null;
    protected ?string $output = null;
    protected array $tags = [];
    protected array $errors = [];
    protected string $transportClass = '';
    protected string $loaderClass = '';
    protected array $middlewareClasses = [];

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

    public function tagWith(string $tag, mixed $val = null): static
    {
        $this->tags[$tag] = $this->tags[$tag] ?? [];
        $this->tags[$tag][] = $val;
        return $this;
    }

    public function tagErrorWith(string $tag, string $mesaage, array $details, ?Throwable $throwable = null): static
    {
        $err = new TransportError(
            $tag,
            $mesaage,
            $details,
            $throwable,
        );
        $this->errors[] = $err;
        $this->tagWith($tag, $mesaage);
        return $this;
    }

    public function getTags(?string $tag = null): array
    {
        if ($tag === null) {
            return $this->tags;
        }
        return $this->tags[$tag] ?? [];
    }

    public function hasTag(string $tag): bool
    {
        return !empty($this->tags[$tag]);
    }

    /**
     * @param TransportError[] $errors
     */
    public function setErrors(array $errors): static
    {
        $this->errors = [];
        foreach ($errors as $error) {
            $this->addError($error);
        }
        return $this;
    }

    public function addError(TransportError $err): static
    {
        $this->errors[] = $err;
        return $this;
    }

    /**
     * @return TransportError[]
     */
    public function getErrors(?string $tag = null): array
    {
        if ($tag === null) {
            return $this->errors;
        }
        return array_values(
            array_filter(
                $this->getErrors(),
                function (TransportError $err) use ($tag) {
                    return $err->tag === $tag;
                },
            ),
        );
    }

    public function hasError(?string $tag = null): bool
    {
        return count($this->getErrors($tag)) > 0;
    }

    public function getSummaryErrorMessage(): string
    {
        if ($this->isValid()) {
            return '';
        }
        if (!$this->hasError()) {
            return 'Invalid WHOIS response';
        }
        $texts = array_map(
            fn(TransportError $err) => $err->toString(),
            $this->getErrors(),
        );
        return implode("\n", $texts);
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
}
