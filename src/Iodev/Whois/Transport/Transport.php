<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

use Iodev\Whois\Transport\Loader\LoaderInterface;
use Iodev\Whois\Transport\Middleware\Request\RequestMiddlewareInterface;
use Iodev\Whois\Transport\Middleware\Response\ResponseMiddlewareInterface;
use \Throwable;

class Transport
{
    protected LoaderInterface $loader;

    /** @var RequestMiddlewareInterface[] */
    protected array $requestMiddlewares = [];

    /** @var ResponseMiddlewareInterface[] */
    protected array $responseMiddlewares = [];

    protected string $stage = TransportStage::COMPLETE;
    protected ?Request $request = null;
    protected ?Response $response = null;

    public function __construct(LoaderInterface $loader)
    {
        $this->loader = $loader;
    }

    public function setLoader(LoaderInterface $loader): static
    {
        $this->loader = $loader;
        return $this;
    }

    public function getLoader(): LoaderInterface
    {
        return $this->loader;
    }

    /**
     * @param RequestMiddlewareInterface[] $middlewares
     */
    public function setRequestMiddlewares(array $middlewares): static
    {
        $this->requestMiddlewares = [];
        foreach ($middlewares as $middleware) {
            $this->addRequestMiddleware($middleware);
        }
        return $this;
    }
    public function addRequestMiddleware(RequestMiddlewareInterface $middleware): static
    {
        $this->requestMiddlewares[] = $middleware;
        return $this;
    }

    /**
     * @return RequestMiddlewareInterface[]
     */
    public function getRequestMiddlewares(): array
    {
        return $this->requestMiddlewares;
    }

    /**
     * @param ResponseMiddlewareInterface[] $middlewares
     */
    public function setResponseMiddlewares(array $middlewares): static
    {
        $this->responseMiddlewares = [];
        foreach ($middlewares as $middleware) {
            $this->addResponseMiddleware($middleware);
        }
        return $this;
    }

    public function addResponseMiddleware(ResponseMiddlewareInterface $middleware): static
    {
        $this->responseMiddlewares[] = $middleware;
        return $this;
    }

    /**
     * @return ResponseMiddlewareInterface[]
     */
    public function getResponseMiddlewares(): array
    {
        return $this->responseMiddlewares;
    }

    public function getResponse(): ?Response
    {
        return $this->response;
    }

    public function sendRequest(Request $request): static
    {
        $this->stage = TransportStage::PREPARING;

        $this->request = null;
        $this->response = null;

        $this->request = $request;
        $this->prepareRequest();

        if ($request->hasTag(RequestTag::COMPLETED)) {
            $this->tagError(ResponseTag::REQUEST_ALREADY_COMPLETED, 'Request was completed before');
            $this->stage = TransportStage::COMPLETE;
            return $this;
        }

        $this->response = $this->newResponse();
        $this->prepareResponse();

        $this->stage = TransportStage::REQUEST_MIDDLEWARING;
        $this->middlewareRequest();

        if ($request->canSend()) {
            $this->stage = TransportStage::LOADING;
            $this->loadOutput();
        } else {
            $this->tagError(ResponseTag::REQUEST_NOT_SENT, 'Request not sent');
        }

        $this->stage = TransportStage::RESPONSE_MIDDLEWARING;
        $this->middlewareResponse();

        $this->stage = TransportStage::COMPLETE;

        return $this;
    }

    protected function prepareRequest(): void
    {
        $this->request->setUsedMiddlewareClasses(
            array_map(
                fn(RequestMiddlewareInterface $item) => $item::class,
                $this->requestMiddlewares,
            ),
        );
    }

    protected function newResponse(): Response
    {
        return new Response();
    }

    protected function prepareResponse(): void
    {
        $this->response
            ->setRequest($this->request)
            ->setUsedTransportClass(static::class)
            ->setUsedLoaderClass($this->loader::class)
            ->setUsedMiddlewareClasses(
                array_map(
                    fn(ResponseMiddlewareInterface $item) => $item::class,
                    $this->responseMiddlewares,
                ),
            )
        ;
    }

    protected function loadOutput(): void
    {
        try {
            $output = $this->loader->loadText(
                $this->request->getHost(),
                $this->request->getQuery(),
            );
            $this->response->setOutput($output);
            $this->request->tagWith(RequestTag::COMPLETED);
        } catch (Throwable $err) {
            $this->tagError(ResponseTag::LOADER_ERROR, 'Unhandled loading error', $err);
        }
    }

    protected function middlewareRequest(): void
    {
        foreach ($this->requestMiddlewares as $middleware) {
            try {
                $middleware->processRequest($this->request);
            } catch (Throwable $err) {
                $this->request->tagWith(RequestTag::MIDDLEWARE_ERROR);
                $this->tagError(ResponseTag::REQUEST_MIDDLEWARE_ERROR, 'Unhandled request middleware error', $err);
            }
        }
    }

    protected function middlewareResponse(): void
    {
        foreach ($this->responseMiddlewares as $middleware) {
            try {
                $middleware->processResponse($this->response);
            } catch (Throwable $err) {
                $this->tagError(ResponseTag::RESPONSE_MIDDLEWARE_ERROR, 'Unhandled response middleware error', $err);
            }
        }
    }

    protected function tagError(string $tag, string $msg, ?Throwable $err = null, array $details = []): void
    {
        $extendedDetails = [
            ...$details,
            'tag' => $tag,
            'message' => $msg,
            'transport_stage' => $this->stage,
            'request_tags' => $this->request->getTags(),
            'response_tags' => $this->response->getTags(),
        ];
        if ($err !== null) {
            $extendedDetails = [
                ...$extendedDetails,
                'error_class' => $err::class,
                'error_code' => $err->getCode(),
                'error_message' => $err->getMessage(),
                'error_stack' => $err->getTraceAsString(),
            ];
        }
        $this->response->tagErrorWith($tag, $msg, $extendedDetails, $err);
    }
}
