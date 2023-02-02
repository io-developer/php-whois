<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Default;


use Iodev\Whois\Whois;

use Iodev\Whois\Config\ConfigProviderInterface;
use Iodev\Whois\Config\ConfigProvider;

use Iodev\Whois\Transport\Transport;
use Iodev\Whois\Transport\Middleware\{
    PrintLogMiddleware,
};
use Iodev\Whois\Transport\Processor\{
    EncodingProcessor,
};
use Iodev\Whois\Transport\Validator\{
    RateLimitValidator,
};
use Iodev\Whois\Transport\Loader\{
    LoaderInterface,
    SocketLoader,
};

use Iodev\Whois\Module\Asn\{
    AsnModule,
    AsnParser,
    AsnServerProvider,
    AsnServerProviderInterface,
};

use Iodev\Whois\Module\Tld\TldModule;
use Iodev\Whois\Module\Tld\Command\{
    LookupCommand,
    WhoisLookupCommand,
};
use Iodev\Whois\Module\Tld\Parsing\{
    AutoParser,
    BlockParser,
    BlockParserOpts,
    CommonParser,
    CommonParserOpts,
    IndentParser,
    IndentParserOpts,
    ParserProviderInterface,
    ParserProvider,
};
use Iodev\Whois\Module\Tld\Whois\{
    QueryBuilder,
    ServerMatcher,
    ServerProviderInterface,
    ServerProvider,
};
use Iodev\Whois\Module\Tld\Tool\LookupInfoScoreCalculator;

use Iodev\Whois\Tool\{
    DateTool,
    DomainTool,
    ParserTool,
    PunycodeToolInterface,
    PunycodeTool,
    TextTool,
};
                  

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

            Transport::class => function() {
                return (new Transport(
                        $this->container->get(LoaderInterface::class),
                    ))
                    ->setMiddlewares([
                        $this->container->get(PrintLogMiddleware::class),
                    ])
                    ->setProcessors([
                        $this->container->get(EncodingProcessor::class),
                    ])
                    ->setValidators([
                        $this->container->get(RateLimitValidator::class),
                    ])
                ;
            },

            LoaderInterface::class => function() {
                return $this->container->get(SocketLoader::class);
            },
            
            EncodingProcessor::class => function() {
                return new EncodingProcessor(
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
                return new TldModule(
                    $this->container,
                    $this->container->get(Transport::class),
                    $this->container->get(ServerProviderInterface::class),
                );
            },

            ServerMatcher::class => function() {
                return new ServerMatcher(
                    $this->container->get(DomainTool::class),
                );
            },

            ServerProviderInterface::class => function() {
                return $this->container->get(ServerProvider::class);
            },

            ServerProvider::class => function() {
                return new ServerProvider(
                    $this->container,
                    $this->container->get(ConfigProviderInterface::class),
                    $this->container->get(ParserProviderInterface::class),
                    $this->container->get(ServerMatcher::class),
                    $this->container->get(Transport::class),
                );
            },

            LookupCommand::class => function() {
                return new LookupCommand(
                    $this->container->get(QueryBuilder::class),
                    $this->container->get(DomainTool::class),
                );
            },

            WhoisLookupCommand::class => function() {
                return new WhoisLookupCommand(
                    $this->container->get(QueryBuilder::class),
                    $this->container->get(DomainTool::class),
                    $this->container->get(ParserTool::class),
                    $this->container->get(DateTool::class),
                );
            },

            ParserProviderInterface::class => function() {
                return $this->container->get(ParserProvider::class);
            },

            ParserProvider::class => function() {
                return new ParserProvider(
                    $this->container,
                );
            },

            CommonParser::class => function() {
                return new CommonParser(
                    $this->container->get(CommonParserOpts::class),
                    $this->container->get(LookupInfoScoreCalculator::class),
                    $this->container->get(ParserTool::class),
                    $this->container->get(DomainTool::class),
                    $this->container->get(DateTool::class),
                );
            },

            BlockParser::class => function() {
                return new BlockParser(
                    $this->container->get(BlockParserOpts::class),
                    $this->container->get(LookupInfoScoreCalculator::class),
                    $this->container->get(ParserTool::class),
                    $this->container->get(DomainTool::class),
                    $this->container->get(DateTool::class),
                );
            },

            IndentParser::class => function() {
                return new IndentParser(
                    $this->container->get(IndentParserOpts::class),
                    $this->container->get(LookupInfoScoreCalculator::class),
                    $this->container->get(ParserTool::class),
                    $this->container->get(DomainTool::class),
                    $this->container->get(DateTool::class),
                );
            },

            AutoParser::class => function() {
                return new AutoParser(
                    $this->container->get(LookupInfoScoreCalculator::class),
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
