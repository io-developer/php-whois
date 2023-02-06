<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin;

use Psr\Container\ContainerExceptionInterface;
use RuntimeException;

class ContainerException extends RuntimeException implements ContainerExceptionInterface
{
}
