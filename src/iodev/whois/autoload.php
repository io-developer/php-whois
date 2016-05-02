<?php

spl_autoload_register(iodev_whois_autoload);

function iodev_whois_autoload( $qname ) {
    $start = 'iodev\\whois\\';
    if (strpos($qname, $start) === 0) {
        $path = str_replace('\\', DIRECTORY_SEPARATOR, substr($qname, strlen($start)));
        $file = __DIR__ . "/$path.php";
        if (is_file($file)) {
            require_once $file;
        }
    }
}
