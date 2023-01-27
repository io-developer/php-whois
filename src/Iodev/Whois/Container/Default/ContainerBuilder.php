<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Default;

use Iodev\Whois\Config\ConfigProviderInterface;
use Iodev\Whois\Config\ConfigProvider;
use Iodev\Whois\Loader\LoaderInterface;
use Iodev\Whois\Loader\ResponseHandler;
use Iodev\Whois\Loader\CurlLoader;
use Iodev\Whois\Loader\SocketLoader;
use Iodev\Whois\Module\Asn\AsnModule;
use Iodev\Whois\Module\Asn\AsnParser;
use Iodev\Whois\Module\Asn\AsnServerProvider;
use Iodev\Whois\Module\Asn\AsnServerProviderInterface;
use Iodev\Whois\Module\Tld\Parser\AutoParser;
use Iodev\Whois\Module\Tld\Parser\BlockParser;
use Iodev\Whois\Module\Tld\Parser\BlockParserOpts;
use Iodev\Whois\Module\Tld\Parser\CommonParser;
use Iodev\Whois\Module\Tld\Parser\CommonParserOpts;
use Iodev\Whois\Module\Tld\Parser\IndentParser;
use Iodev\Whois\Module\Tld\Parser\IndentParserOpts;
use Iodev\Whois\Module\Tld\TldInfoRankCalculator;
use Iodev\Whois\Module\Tld\TldLoader;
use Iodev\Whois\Module\Tld\TldModule;
use Iodev\Whois\Module\Tld\TldParserProvider;
use Iodev\Whois\Module\Tld\TldParserProviderInterface;
use Iodev\Whois\Module\Tld\TldServerMatcher;
use Iodev\Whois\Module\Tld\TldServerProvider;
use Iodev\Whois\Module\Tld\TldServerProviderInterface;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Tool\ParserTool;
use Iodev\Whois\Tool\PunycodeTool;
use Iodev\Whois\Tool\PunycodeToolInterface;
use Iodev\Whois\Tool\TextTool;
use Iodev\Whois\Whois;
                                                               
class ContainerBuilder
{
    protected $container;

    public function __construct()
    {
        $this->container = new Container();
    }

    public function getContainer(): Container
    {
        return $this->container;
    }

    public function configure(): static
    {
        $this->container->bindMany([
            Container::ID_COMMON_CLASS_INSTANTIATOR => fn($clName) => new $clName(),

            ConfigProviderInterface::class => function() {
                return $this->container->get(ConfigProvider::class);
            },

            PunycodeToolInterface::class => function() {
                return $this->container->get(PunycodeTool::class);
            },

            LoaderInterface::class => function() {
                return $this->container->get(SocketLoader::class);
            },

            SocketLoader::class => function() {
                return new SocketLoader(
                    $this->container->get(ResponseHandler::class),
                );
            },

            CurlLoader::class => function() {
                return new CurlLoader(
                    $this->container->get(ResponseHandler::class),
                );
            },
            
            ResponseHandler::class => function() {
                return new ResponseHandler(
                    $this->container->get(TextTool::class),
                );
            },

            Whois::class => function() {
                $instance = new Whois(
                    $this->container,
                    $this->container->get(TldModule::class),
                    $this->container->get(AsnModule::class),
                );
                return $instance;
            },

            TldModule::class => function() {
                /** @var TldServerProviderInterface */
                $serverProvider = $this->container->get(TldServerProviderInterface::class);

                return new TldModule(
                    $this->container->get(TldLoader::class),
                    $serverProvider->getCollection(),
                    $this->container->get(TldServerMatcher::class),
                );
            },

            TldLoader::class => function() {
                return new TldLoader(
                    $this->container->get(LoaderInterface::class),
                    $this->container->get(DomainTool::class),
                );
            },

            TldServerMatcher::class => function() {
                return new TldServerMatcher(
                    $this->container->get(DomainTool::class),
                );
            },

            TldServerProviderInterface::class => function() {
                return $this->container->get(TldServerProvider::class);
            },

            TldServerProvider::class => function() {
                return new TldServerProvider(
                    $this->container,
                    $this->container->get(TldParserProviderInterface::class),
                );
            },

            TldParserProviderInterface::class => function() {
                return $this->container->get(TldParserProvider::class);
            },

            TldParserProvider::class => function() {
                return new TldParserProvider(
                    $this->container,
                );
            },

            CommonParser::class => function() {
                return new CommonParser(
                    $this->container->get(CommonParserOpts::class),
                    $this->container->get(TldInfoRankCalculator::class),
                    $this->container->get(ParserTool::class),
                    $this->container->get(DomainTool::class),
                    $this->container->get(DateTool::class),
                );
            },

            BlockParser::class => function() {
                return new BlockParser(
                    $this->container->get(BlockParserOpts::class),
                    $this->container->get(TldInfoRankCalculator::class),
                    $this->container->get(ParserTool::class),
                    $this->container->get(DomainTool::class),
                    $this->container->get(DateTool::class),
                );
            },

            IndentParser::class => function() {
                return new IndentParser(
                    $this->container->get(IndentParserOpts::class),
                    $this->container->get(TldInfoRankCalculator::class),
                    $this->container->get(ParserTool::class),
                    $this->container->get(DomainTool::class),
                    $this->container->get(DateTool::class),
                );
            },

            AutoParser::class => function() {
                return new AutoParser(
                    $this->container->get(TldInfoRankCalculator::class),
                );
            },

            AsnModule::class => function() {
                /** @var AsnServerProviderInterface */
                $provider = $this->container->get(AsnServerProviderInterface::class);
                $servers = $provider->getList();

                $instance = new AsnModule(
                    $this->container->get(LoaderInterface::class),
                );
                $instance->setServers($servers);
                return $instance;
            },

            AsnServerProviderInterface::class => function() {
                return $this->container->get(AsnServerProvider::class);
            },

            AsnServerProvider::class => function() {
                return new AsnServerProvider(
                    $this->container,
                );
            },

            AsnParser::class => function() {
                return new AsnParser(
                    $this->container->get(ParserTool::class),
                );
            },

            DomainTool::class => function() {
                return new DomainTool(
                    $this->container->get(PunycodeToolInterface::class),
                );
            },
        ]);

        return $this;
    }
}
