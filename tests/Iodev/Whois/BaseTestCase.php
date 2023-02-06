<?php

declare(strict_types=1);

namespace Iodev\Whois;

use Iodev\Whois\Container\Builtin\Container;
use Iodev\Whois\Container\Builtin\ContainerBuilder;
use Iodev\Whois\Transport\Loader\FakeSocketLoader;
use Iodev\Whois\Transport\Loader\LoaderInterface;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Tool\ParserTool;
use Iodev\Whois\Config\ConfigProvider;
use Iodev\Whois\Config\ConfigProviderInterface;
use Iodev\Whois\Module\Tld\Parsing\ParserProviderInterface;
use Iodev\Whois\Module\Tld\Parsing\CommonParserOpts;
use Iodev\Whois\Module\Tld\Parsing\TestCommonParser;
use Iodev\Whois\Module\Tld\Tool\LookupInfoScoreCalculator;
use Iodev\Whois\Module\Tld\Whois\ServerMatcher;
use Iodev\Whois\Module\Tld\Whois\ServerProvider;
use Iodev\Whois\Module\Tld\Whois\ServerProviderInterface;
use Iodev\Whois\Transport\Middleware\Response\EncodingProcessor;
use Iodev\Whois\Transport\Middleware\Response\RateLimitChecker;
use Iodev\Whois\Transport\Transport;
use PHPUnit\Framework\TestCase;

abstract class BaseTestCase extends TestCase
{
    protected Container $container;
    protected ConfigProvider $configProvider;
    protected FakeSocketLoader $loader;
    protected Transport $transport;
    protected Whois $whois;


    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);

        $this->container = static::getContainer();
        $this->configProvider = static::getConfigProvider();
        $this->loader = static::getLoader();
        $this->transport = static::getTransport();
        $this->whois = static::getWhois();

        $this->onConstructed();
    }

    /**
     * To skip every time copy-paste __construct params on constructor overriding
     */
    protected function onConstructed()
    {
    }

    protected static function getContainer(): Container
    {
        static $container = null;

        if ($container === null) {
            $container = (new ContainerBuilder())
                ->configure()
                ->getContainer()
            ;
            $container->bindMany([
                LoaderInterface::class => function() {
                    return static::getLoader();
                },

                Transport::class => function() {
                    return static::getTransport();
                },

                TestCommonParser::class => function() use ($container) {
                    return new TestCommonParser(
                        $container->get(CommonParserOpts::class),
                        $container->get(LookupInfoScoreCalculator::class),
                        $container->get(ParserTool::class),
                        $container->get(DomainTool::class),
                        $container->get(DateTool::class),
                    );
                },

                ServerProviderInterface::class => function() use ($container) {
                    return $container->get(ServerProvider::class);
                },

                ServerProvider::class => function() use ($container) {
                    $instance = new ServerProvider(
                        $container,
                        $container->get(ConfigProviderInterface::class),
                        $container->get(ParserProviderInterface::class),
                        $container->get(ServerMatcher::class),
                        $container->get(Transport::class),
                    );
                    $instance->setWhoisUpdateEnabled(false);
                    return $instance;
                },
            ]);
        }
        return $container;
    }

    protected static function getConfigProvider(): ConfigProvider
    {
        static $configProvider = null;

        if ($configProvider === null) {
            $configProvider = static::getContainer()->get(ConfigProvider::class);
        }
        return $configProvider;
    }

    protected static function getLoader(): FakeSocketLoader
    {
        static $loader = null;

        if ($loader === null) {
            $loader = new FakeSocketLoader();
        }
        return $loader;
    }

    protected static function getTransport(): Transport
    {
        /** @var Transport */
        static $transport = null;

        if ($transport === null) {
            /** @var Transport */
            $transport = new Transport(static::getLoader());
            $transport->setRequestMiddlewares([]);
            $transport->setResponseMiddlewares([
                static::getContainer()->get(EncodingProcessor::class),
                static::getContainer()->get(RateLimitChecker::class),
            ]);
        }
        return $transport;
    }

    protected static function getWhois(): Whois
    {
        static $whois = null;

        if ($whois === null) {
            $whois = static::getContainer()->get(Whois::class);
        }
        return $whois;
    }
}