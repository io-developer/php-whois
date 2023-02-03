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

        $this->response = $this->newResponse();
        $this->prepareResponse();

        if ($request->getState() !== RequestState::NEW) {
            $this->tagError(ResponseTag::REQUEST_HAS_INVALID_STATE, 'Request state is not NEW');
            $this->stage = TransportStage::COMPLETE;
            return $this;
        }

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
        $this->request->setState(RequestState::NEW, true);
        $this->request->setMiddlewareClasses(
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
            ->setTransportClass(static::class)
            ->setLoaderClass($this->loader::class)
            ->setMiddlewareClasses(
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
        } catch (Throwable $err) {
            $this->tagError(ResponseTag::REQUEST_NOT_SENT, 'Unhandled loading error', $err);
        }
    }

    protected function middlewareRequest(): void
    {
        foreach ($this->requestMiddlewares as $middleware) {
            try {
                $middleware->processRequest($this->request);
            } catch (Throwable $err) {
                $this->request->setState(RequestState::MIDDLEWARE_ERROR);
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
            'request_state' => $this->request->getState(),
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
