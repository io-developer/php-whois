<?php

use Iodev\Whois\Factory;

$scriptDir = '.';
if (preg_match('~^(.+?)/[^/]+$~ui', $_SERVER['SCRIPT_FILENAME'], $m)) {
    $scriptDir = $m[1];
}
include "$scriptDir/../vendor/autoload.php";

$action = trim($argv[1] ?? '');
$args = array_slice($argv, 2);

if (empty($action)) {
    $action = 'help';
}

switch (mb_strtolower(ltrim($action, '-'))) {
    case 'help':
    case 'h':
        echo implode("\n", [
            'Welcome to php-whois CLI',
            '',
            '  Syntax:',
            '    php-whois {action} [arg1 arg2 ... argN]',
            '    php-whois help|--help|-h',
            '    php-whois lookup {domain}',
            '    php-whois info {domain}',
            '',
            '  Examples',
            '    php-whois lookup google.com',
            '    php-whois info google.com',
            '',
            '',
        ]);
        exit;
}

$whois = Factory::get()->createWhois();

switch ($action) {
    case 'lookup':
        echo "action: {$action}\n";
        echo "domain: '{$args[0]}'\n\n";
        var_dump($whois->lookupDomain($args[0]));
        break;

    case 'info':
        echo "action: {$action}\n";
        echo "domain: '{$args[0]}'\n\n";
        var_dump($whois->loadDomainInfo($args[0]));
        break;

    default:
        echo "Unknown action: {$action}\n";
        exit(1);
}
