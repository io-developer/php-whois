<?php

declare(strict_types=1);

namespace Iodev\Whois\Routing;

interface LookupResponseInterface
{
    public function getModule(): string;
    public function getLookupRequest();
    public function getLookupInfo();
    public function getTransportResponse();
}
