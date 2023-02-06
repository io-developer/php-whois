<?php

declare(strict_types=1);

namespace Iodev\Whois\Traits;

use \Iodev\Whois\Error\Error;
use \Throwable;

trait TagErrorContainerTrait
{
    use TagContainerTrait;
    use ErrorContainerTrait;

    public function tagErrorWith(string $tag, string $mesaage, array $details, ?Throwable $throwable = null): static
    {
        $err = new Error(
            $tag,
            $mesaage,
            $details,
            $throwable,
        );
        $this->errors[] = $err;
        $this->tagWith($tag, $mesaage);
        return $this;
    }
}
