<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Middleware;

use Iodev\Whois\Transport\Request;
use Iodev\Whois\Transport\Response;

class PrintLogMiddleware implements MiddlewareInterface
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
            ],
            'response' => [
                'isValid' => (int)$response->isValid(),
                'summaryErrorMsg' => $response->getSummaryErrorMessage(),
                'transportClass' => $response->getTransportClass(),
                'loaderClass' => $response->getLoaderClass(),
                'middlewareClasses' => $response->getMiddlewareClasses(),
                'processorClasses' => $response->getProcessorClasses(),
                'validatorClasses' => $response->getValidatorClasses(),
                'output' => $response->getOutput(),
            ],
        ]);
    }
}
