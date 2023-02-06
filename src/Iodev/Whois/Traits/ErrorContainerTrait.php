<?php

declare(strict_types=1);

namespace Iodev\Whois\Traits;

use \Iodev\Whois\Error\Error;

trait ErrorContainerTrait
{
    use TagContainerTrait;

    protected array $errors = [];

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
    public function getErrors(?string $idOrTag = null): array
    {
        if ($idOrTag === null) {
            return $this->errors;
        }
        return array_values(
            array_filter(
                $this->getErrors(),
                function (Error $err) use ($idOrTag) {
                    return $err->id === $idOrTag;
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
            fn(Error $err) => $err->toString(),
            $this->getErrors(),
        );
        return implode("\n", $texts);
    }
}
