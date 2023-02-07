<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin\Configurator;

use \Iodev\Whois\Container\Builtin\Container;
use \Iodev\Whois\Config\{
    ConfigProviderInterface,
};
use \Iodev\Whois\Module\Tld\{
    TldModule,

    Command\LookupCommand,
    Command\WhoisLookupCommand,

    Parsing\ParserProviderInterface,
    Parsing\ParserProvider,
    Parsing\AutoParser,
    Parsing\CommonParser,
    Parsing\CommonParserOpts,
    Parsing\BlockParser,
    Parsing\BlockParserOpts,
    Parsing\IndentParser,
    Parsing\IndentParserOpts,

    Tool\LookupInfoScoreCalculator,

    Whois\QueryBuilder,
    Whois\ServerMatcher,
    Whois\ServerProvider,
    Whois\ServerProviderInterface,
};
use \Iodev\Whois\Transport\{
    Transport,
};
use \Iodev\Whois\Tool\{
    DateTool,
    DomainTool,
    ParserTool,
};

class ModuleTldConfigurator implements ConfiguratorInterface
{
    public function configureContainer(Container $container): void
    {
        $container->bindMany([
            TldModule::class => function (Container $container, string $id) {
                return new TldModule(
                    $container,
                    $container->get(Transport::class),
                    $container->get(ServerProviderInterface::class),
                );
            },

            ServerMatcher::class => function (Container $container, string $id) {
                return new ServerMatcher(
                    $container->get(DomainTool::class),
                );
            },

            ServerProviderInterface::class => function (Container $container, string $id) {
                return $container->get(ServerProvider::class);
            },

            ServerProvider::class => function (Container $container, string $id) {
                return new ServerProvider(
                    $container,
                    $container->get(ConfigProviderInterface::class),
                    $container->get(ParserProviderInterface::class),
                    $container->get(ServerMatcher::class),
                    $container->get(Transport::class),
                );
            },

            LookupCommand::class => function (Container $container, string $id) {
                return new LookupCommand(
                    $container->get(QueryBuilder::class),
                    $container->get(DomainTool::class),
                );
            },

            WhoisLookupCommand::class => function (Container $container, string $id) {
                return new WhoisLookupCommand(
                    $container->get(QueryBuilder::class),
                    $container->get(DomainTool::class),
                    $container->get(ParserTool::class),
                    $container->get(DateTool::class),
                );
            },

            ParserProviderInterface::class => function (Container $container, string $id) {
                return $container->get(ParserProvider::class);
            },

            ParserProvider::class => function (Container $container, string $id) {
                return new ParserProvider(
                    $container,
                );
            },

            CommonParser::class => function(Container $container, string $id) {
                return new CommonParser(
                    $container->get(CommonParserOpts::class),
                    $container->get(LookupInfoScoreCalculator::class),
                    $container->get(ParserTool::class),
                    $container->get(DomainTool::class),
                    $container->get(DateTool::class),
                );
            },

            BlockParser::class => function(Container $container, string $id) {
                return new BlockParser(
                    $container->get(BlockParserOpts::class),
                    $container->get(LookupInfoScoreCalculator::class),
                    $container->get(ParserTool::class),
                    $container->get(DomainTool::class),
                    $container->get(DateTool::class),
                );
            },

            IndentParser::class => function(Container $container, string $id) {
                return new IndentParser(
                    $container->get(IndentParserOpts::class),
                    $container->get(LookupInfoScoreCalculator::class),
                    $container->get(ParserTool::class),
                    $container->get(DomainTool::class),
                    $container->get(DateTool::class),
                );
            },

            AutoParser::class => function(Container $container, string $id) {
                return new AutoParser(
                    $container->get(LookupInfoScoreCalculator::class),
                );
            },
        ]);
    }
}
