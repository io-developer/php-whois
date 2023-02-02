<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

use Iodev\Whois\Transport\Loader\LoaderInterface;
use Iodev\Whois\Transport\Error\Error;
use Iodev\Whois\Transport\Error\ErrorType;
use Iodev\Whois\Transport\Middleware\MiddlewareInterface;
use Iodev\Whois\Transport\Processor\ProcessorInterface;
use Iodev\Whois\Transport\Validator\ValidatorInterface;

class Transport
{
    protected LoaderInterface $loader;

    /** @var MiddlewareInterface[] */
    protected array $middlewares = [];

    /** @var ProcessorInterface[] */
    protected array $processors = [];

    /** @var ValidatorInterface[] */
    protected array $validators = [];

    protected ?Request $request = null;
    protected ?Response $response = null;
    protected ?string $output = null;

    /** @var Error[] */
    protected array $errors = [];


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
     * @param MiddlewareInterface[] $middlewares
     */
    public function setMiddlewares(array $middlewares): static
    {
        $this->middlewares = [];
        foreach ($middlewares as $middleware) {
            $this->addMiddleware($middleware);
        }
        return $this;
    }

    public function addMiddleware(MiddlewareInterface $middleware): static
    {
        $this->middlewares[] = $middleware;
        return $this;
    }

    /**
     * @return MiddlewareInterface[]
     */
    public function getMiddlewares(): array
    {
        return $this->middlewares;
    }


    /**
     * @param ProcessorInterface[] $processors
     */
    public function setProcessors(array $processors): static
    {
        $this->processors = [];
        foreach ($processors as $processor) {
            $this->addProcessor($processor);
        }
        return $this;
    }

    public function addProcessor(ProcessorInterface $processor): static
    {
        $this->processors[] = $processor;
        return $this;
    }

    /**
     * @return ProcessorInterface[]
     */
    public function getProcessors(): array
    {
        return $this->processors;
    }


    /**
     * @param ValidatorInterface[] $validators
     */
    public function setValidators(array $validators): static
    {
        $this->validators = [];
        foreach ($validators as $validator) {
            $this->addValidator($validator);
        }
        return $this;
    }

    public function addValidator(ValidatorInterface $validator): static
    {
        $this->validators[] = $validator;
        return $this;
    }

    /**
     * @return ValidatorInterface[]
     */
    public function getValidators(): array
    {
        return $this->validators;
    }


    public function getResponse(): ?Response
    {
        return $this->response;
    }

    public function sendRequest(Request $request): static
    {
        $this->request = $request;
        $this->response = null;
        $this->output = null;
        $this->errors = [];

        $this->middlewareRequest();

        if (!$request->getCancelled()) {
            $this->loadOutput();
            $this->processOutput();
            $this->validateOutput();
        }

        $this->response = $this->createResponse();
        $this->fillResponse();

        $this->middlewareResponse();

        return $this;
    }

    protected function createResponse(): Response
    {
        return new Response();
    }

    protected function fillResponse(): void
    {
        $this->response
            ->setRequest($this->request)
            ->setOutput($this->output)
            ->setErrors($this->errors)
            ->setTransportClass(static::class)
            ->setLoaderClass($this->loader::class)
            ->setMiddlewareClasses(array_map(
                fn(MiddlewareInterface $item) => $item::class,
                $this->middlewares,
            ))
            ->setProcessorClasses(array_map(
                fn(ProcessorInterface $item) => $item::class,
                $this->processors,
            ))
            ->setValidatorClasses(array_map(
                fn(ValidatorInterface $item) => $item::class,
                $this->validators,
            ))
        ;
    }

    protected function loadOutput(): void
    {
        $this->output = null;
        try {
            $this->output = $this->loader->loadText(
                $this->request->getHost(),
                $this->request->getQuery(),
            );
        } catch (\Throwable $err) {
            $this->errors[] = new Error(
                ErrorType::LOADING,
                $this->loader::class,
                $err->getMessage(),
                ['Unhandled WHOIS output loading error'],
                $err,
            );
        }
    }

    protected function middlewareRequest(): void
    {
        foreach ($this->middlewares as $middleware) {
            try {
                $middleware->processRequest($this->request);
            } catch (\Throwable $err) {
                $this->request->setCancelled(true);

                $this->errors[] = new Error(
                    ErrorType::REQUEST_MIDDLEWARING,
                    $middleware::class,
                    $err->getMessage(),
                    ['Unhandled WHOIS request middlewaring error'],
                    $err,
                );
            }
        }
    }

    protected function middlewareResponse(): void
    {
        foreach ($this->middlewares as $middleware) {
            try {
                $middleware->processResponse($this->response);
            } catch (\Throwable $err) {
                $this->response->addError(
                    new Error(
                        ErrorType::REQUEST_MIDDLEWARING,
                        $middleware::class,
                        $err->getMessage(),
                        ['Unhandled WHOIS request middlewaring error'],
                        $err,
                    )
                );
            }
        }
    }

    protected function processOutput(): void
    {
        foreach ($this->processors as $processor) {
            try {
                $this->output = $processor->processOutput($this->output);
            } catch (\Throwable $err) {
                $this->errors[] = new Error(
                    ErrorType::OUTPUT_PROCESSING,
                    $processor::class,
                    $err->getMessage(),
                    ['Unhandled WHOIS output processing error'],
                    $err,
                );
            }
        }
    }

    protected function validateOutput(): void
    {
        foreach ($this->validators as $validator) {
            try {
                $errorDetails = [];
                $validator->validateOutput($this->output);
                foreach ($validator->getErrorDetails() as $error) {
                    $errorDetails[] = $error;
                }
                if (count($errorDetails) > 0) {
                    $this->errors[] = new Error(
                        ErrorType::OUTPUT_VALIDATION,
                        $validator::class,
                        'WHOIS output validation error',
                        $errorDetails,
                        null,
                    );
                }
            } catch (\Throwable $err) {
                $this->errors[] = new Error(
                    ErrorType::OUTPUT_VALIDATION,
                    $validator::class,
                    $err->getMessage(),
                    ['Unhandled WHOIS output validation error'],
                    $err,
                );
            }
        }
    }

}
