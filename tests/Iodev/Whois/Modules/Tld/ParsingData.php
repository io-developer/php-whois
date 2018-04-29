<?php

namespace Iodev\Whois\Modules\Tld;

use InvalidArgumentException;

class ParsingData
{
    /**
     * @param $filename
     * @return string
     * @throws InvalidArgumentException
     */
    public static function loadContent($filename)
    {
        $file = __DIR__ . '/parsing_data/' . $filename;
        if (!file_exists($file)) {
            throw new InvalidArgumentException("File '$file' not found");
        }
        return file_get_contents($file);
    }
}