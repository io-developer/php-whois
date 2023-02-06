<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Middleware;

use Iodev\Whois\Transport\Middleware\Request\RequestMiddlewareInterface;
use Iodev\Whois\Transport\Middleware\Response\ResponseMiddlewareInterface;
use Iodev\Whois\Transport\Request;
use Iodev\Whois\Transport\Response;

class PrintLog implements RequestMiddlewareInterface, ResponseMiddlewareInterface
{
    public function processRequest(Request $request): void
    {
        print_r([
            'time' => date(DATE_ATOM),
            'microtime' => sprintf('%.3f', microtime(true)),
            'message' => 'WHOIS Request',
            'request' => [
                'host' => $request->getHost(),
                'port' => $request->getPort(),
                'timeout' => $request->getTimeout(),
                'query' => $request->getQuery(),
            ],
        ]);
    }

    public function processResponse(Response $response): void
    {
        $request = $response->getRequest();

        print_r([
            'time' => date(DATE_ATOM),
            'microtime' => sprintf('%.3f', microtime(true)),
            'message' => 'WHOIS Response',
            'request' => [
                'host' => $request->getHost(),
                'port' => $request->getPort(),
                'timeout' => $request->getTimeout(),
                'query' => $request->getQuery(),
                'tags' => $request->getTags(),
                'usedMiddlewareClasses' => $request->getUsedMiddlewareClasses(),
            ],
            'response' => [
                'isValid' => (int)$response->isValid(),
                'summaryErrorMsg' => $response->getSummaryErrorMessage(),
                'tags' => $response->getTags(),
                'usedTransportClass' => $response->getUsedTransportClass(),
                'usedLoaderClass' => $response->getUsedLoaderClass(),
                'usedMiddlewareClasses' => $response->getUsedMiddlewareClasses(),
                'output' => $response->getOutput(),
            ],
        ]);
    }
}
