<?php

use Iodev\Whois\Factory;

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
            info($args[0], $opts['parser'] ?? null);
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

function help()
{
    echo implode("\n", [
        'Welcome to php-whois CLI',
        '',
        '  Syntax:',
        '    php-whois {action} [arg1 arg2 ... argN]',
        '    php-whois help|--help|-h',
        '    php-whois lookup {domain}',
        '    php-whois info {domain} [--parser {type}]',
        '',
        '  Examples',
        '    php-whois lookup google.com',
        '    php-whois info google.com',
        '    php-whois info google.com --parser block',
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

    $whois = Factory::get()->createWhois();
    $result = $whois->lookupDomain($domain);

    var_dump($result);
}

function info(string $domain, string $parserType = null)
{
    echo implode("\n", [
        '  action: info',
        "  domain: '{$domain}'",
        "  parser: '{$parserType}'",
        '',
        '',
    ]);

    $tld = Factory::get()->createWhois()->getTldModule();
    if ($parserType) {
        try {
            $parser = Factory::get()->createTldParser($parserType);
        } catch (\Throwable $e) {
            echo "\nCannot create TLD parser with type '$parserType'\n\n";
            throw $e;
        }
        $newServers = [];
        foreach ($tld->getServers() as $server) {
            $newServers[] = new \Iodev\Whois\Modules\Tld\TldServer(
                $server->getZone(),
                $server->getHost(),
                $server->isCentralized(),
                $parser,
                $server->getQueryFormat()
            );
        }
        $tld->setServers($newServers);
    }

    $result = $tld->loadDomainInfo($domain);

    var_dump($result);
}

main($argv);


