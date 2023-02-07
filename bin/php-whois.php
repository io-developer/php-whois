<?php

declare(strict_types=1);

use Iodev\Whois\Container\Builtin\Container;
use Iodev\Whois\Container\Builtin\ContainerProvider;
use Iodev\Whois\Transport\Loader\LoaderInterface;
use Iodev\Whois\Transport\Loader\FakeSocketLoader;
use Iodev\Whois\Module\Tld\TldModule;
use Iodev\Whois\Module\Tld\Parsing\ParserProviderInterface;
use Iodev\Whois\Whois;


$scriptDir = '.';
if (preg_match('~^(.+?)/[^/]+$~ui', $_SERVER['SCRIPT_FILENAME'], $m)) {
    $scriptDir = $m[1];
}
include "$scriptDir/../vendor/autoload.php";

function main($argv)
{
    $action = trim($argv[1] ?? '');
    $args = array_slice($argv, 2);

    if (empty($action)) {
        $action = 'help';
    }
    switch (mb_strtolower(ltrim($action, '-'))) {
        case 'help':
        case 'h':
            help();
            return;
    }
    switch ($action) {
        case 'lookup':
            lookup($args[0]);
            break;

        case 'info':
            $opts = parseOpts(implode(' ', array_slice($args, 1)));
            info($args[0], $opts);
            break;

        default:
            echo "Unknown action: {$action}\n";
            exit(1);
    }
}

function parseOpts(string $str): array
{
    $result = [];
    $rest = trim($str);
    while (preg_match('~--([-_a-z\d]+)(\s+|=)(\'([^\']+)\'|[^-\s]+)~ui', $rest, $m, PREG_OFFSET_CAPTURE)) {
        $result[$m[1][0]] = $m[4][0] ?? $m[3][0];
        $rest = trim(mb_substr($rest, $m[0][1] + mb_strlen($m[0][0])));
    }
    return $result;
}

function getContainer(): Container
{
    return ContainerProvider::get()->getContainer();
}

function help()
{
    echo implode("\n", [
        'Welcome to php-whois CLI',
        '',
        '  Syntax:',
        '    php-whois {action} [arg1 arg2 ... argN]',
        '    php-whois help|--help|-h',
        '    php-whois lookup {domain}',
        '    php-whois info {domain} [--parser {type}] [--host {whois}]',
        '',
        '  Examples',
        '    php-whois lookup google.com',
        '    php-whois info google.com',
        '    php-whois info google.com --parser block',
        '    php-whois info ya.ru --host whois.nic.ru --parser auto',
        '',
        '',
    ]);
}

function lookup(string $domain)
{
    echo implode("\n", [
        '  action: lookup',
        "  domain: '{$domain}'",
        '',
        '',
    ]);

    $whois = getContainer()->get(Whois::class);
    $result = $whois->lookupDomain($domain);

    var_dump($result);
}

function info(string $domain, array $options = [])
{
    $options = array_replace([
        'host' => null,
        'parser' => null,
        'file' => null,
    ], $options);

    echo implode("\n", [
        '  action: info',
        "  domain: '{$domain}'",
        sprintf("  options: %s", json_encode($options, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)),
        '',
        '',
    ]);

    if ($options['file']) {
        getContainer()->bind(LoaderInterface::class, function() use ($options) {
            $loader = new FakeSocketLoader();
            $loader->text = file_get_contents($options['file']);
            return $loader;
        });
    }

    /** @var TldModule */
    $tld = getContainer()->get(TldModule::class);

    $parser = null;
    if (!empty($options['parser'])) {
        try {
            /** @var ParserProviderInterface */
            $tldParserProvider = getContainer()->get(ParserProviderInterface::class);
            $parser = $tldParserProvider->getByType($options['parser']);
        } catch (\Throwable $e) {
            echo "\nCannot create TLD parser with type '{$options['parser']}'\n\n";
            throw $e;
        }
    }

    $host = $options['host'] ?? null;

    $result = $tld->lookupDomain($domain, $host, null, $parser);

    var_dump($result->info);
}

main($argv);


