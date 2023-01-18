<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Default;

use Exception;
use Psr\Container\NotFoundExceptionInterface;

class NotFoundException extends Exception implements NotFoundExceptionInterface
{
}
