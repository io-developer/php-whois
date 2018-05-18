<?php

namespace Iodev\Whois\Helpers;

class ParserHelper
{
    /**
     * @param $text
     * @return string[]
     */
    public static function splitLines($text)
    {
        return preg_split('~\r\n|\r|\n~ui', strval($text));
    }
}
