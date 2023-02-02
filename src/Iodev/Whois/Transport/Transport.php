<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

use Iodev\Whois\Transport\Loader\LoaderInterface;
use Iodev\Whois\Transport\Processor\ProcessorInterface;
use Iodev\Whois\Transport\Validator\ValidatorInterface;

class Transport
{
    protected LoaderInterface $loader;

    /** @var ProcessorInterface[] */
    protected array $processors = [];

    /** @var ValidatorInterface[] */
    protected array $validators = [];

    protected string $output = '';
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


    public function addProcessor(ProcessorInterface $processor): static
    {
        $this->processors[] = $processor;
        return $this;
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

    /**
     * @return ProcessorInterface[]
     */
    public function getProcessors(): array
    {
        return $this->processors;
    }


    public function addValidator(ValidatorInterface $validator): static
    {
        $this->validators[] = $validator;
        return $this;
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
        $this->response = null;
        $errors = [];

        $output = $this->loadOutput($request, $errors);
        $output = $this->processOutput($output, $errors);
        $this->validateOutput($output, $errors);

        $this->response = $this->createResponse()
            ->setRequest($request)
            ->setOutput($output)
            ->setErrors($errors)
            ->setLoaderClass($this->loader::class)
            ->setProcessorClasses(array_map(
                fn(ProcessorInterface $item) => $item::class,
                $this->processors,
            ))
            ->setValidatorClasses(array_map(
                fn(ValidatorInterface $item) => $item::class,
                $this->validators,
            ))
        ;
        return $this;
    }

    protected function createResponse(): Response
    {
        return new Response();
    }

    protected function loadOutput(Request $request, array &$outErrors): string
    {
        $output = '';
        try {
            $output = $this->loader->loadText($request->getHost(), $request->getQuery());
        } catch (\Throwable $err) {
            $outErrors[] = new Error(
                Error::TYPE_LOADING,
                $this->loader::class,
                $err->getMessage(),
                ['Unhandled WHOIS output loading error'],
                $err,
            );
        }
        return $output;
    }

    protected function processOutput(string $output, array &$outErrors): string
    {
        foreach ($this->processors as $processor) {
            try {
                $output = $processor->processOutput($output);
            } catch (\Throwable $err) {
                $outErrors[] = new Error(
                    Error::TYPE_PROCESSING,
                    $processor::class,
                    $err->getMessage(),
                    ['Unhandled WHOIS output processing error'],
                    $err,
                );
            }
        }
        return $output;
    }

    protected function validateOutput(string $output, array &$outErrors): void
    {
        foreach ($this->validators as $validator) {
            try {
                $errorDetails = [];
                $validator->validateOutput($output);
                foreach ($validator->getErrorDetails() as $error) {
                    $errorDetails[] = $error;
                }
                if (count($errorDetails) > 0) {
                    $outErrors[] = new Error(
                        Error::TYPE_VALIDATION,
                        $validator::class,
                        'WHOIS output validation error',
                        $errorDetails,
                        null,
                    );
                }
            } catch (\Throwable $err) {
                $outErrors[] = new Error(
                    Error::TYPE_VALIDATION,
                    $validator::class,
                    $err->getMessage(),
                    ['Unhandled WHOIS output validation error'],
                    $err,
                );
            }
        }
    }

}
