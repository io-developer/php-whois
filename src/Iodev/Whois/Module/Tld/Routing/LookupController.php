<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Routing;

use Iodev\Whois\Module\Tld\NewCommand\LookupCommand;
use Iodev\Whois\Module\Tld\NewCommand\SingleLookupCommand;
use Iodev\Whois\Module\Tld\NewDto\LookupRequestData;
use Iodev\Whois\Module\Tld\NewDto\LookupResponse;
use Iodev\Whois\Module\Tld\NewDto\SingleLookupRequestData;
use Iodev\Whois\Module\Tld\NewDto\SingleLookupResponse;
use Iodev\Whois\Module\Tld\Parsing\ParserProviderInterface;
use Iodev\Whois\Routing\LookupResponseInterface;
use Iodev\Whois\Transport\Transport;
use Psr\Container\ContainerInterface;

class LookupController
{
    public function __construct(
        protected ContainerInterface $container,
        protected Transport $transport,
        protected ParserProviderInterface $parserProvider,
    ) {}

    public function preRoute(mixed $req): void
    {
    }

    public function route(mixed $req): ?LookupResponseInterface
    {
        return null;
    }

    public function lookup(mixed $req, LookupRequestData $data): LookupResponse
    {
        return $this->makeCommand()
            ->setRequestData($data)
            ->setTransport($this->transport)
            ->setParserProvider($this->parserProvider)
            ->execute()
            ->getResponse()
        ;
    }

    public function lookupSingle(mixed $req, SingleLookupRequestData $data): SingleLookupResponse
    {
        return $this->makeSingleCommand()
            ->setRequestData($data)
            ->setTransport($this->transport)
            ->setParser(null)
            ->execute()
            ->getResponse()
        ;
    }

    protected function makeCommand(): LookupCommand
    {
        return $this->container->get(LookupCommand::class);
    }

    protected function makeSingleCommand(): SingleLookupCommand
    {
        return $this->container->get(SingleLookupCommand::class);
    }
}
