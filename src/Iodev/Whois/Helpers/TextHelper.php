<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

class TextHelper
{
    public static function toUtf8(string $text): string
    {
        $srcEncoding = mb_detect_encoding($text);
        if (!empty($srcEncoding) && strtolower($srcEncoding) !== 'utf-8') {
            return mb_convert_encoding($text, 'utf-8', strtolower($srcEncoding));
        }
        if (mb_check_encoding($text, 'utf-8')) {
            return $text;
        }
        if (mb_check_encoding($text, 'windows-1252')) {
            return iconv('windows-1252', 'utf-8', $text);
        }
        if (mb_check_encoding($text, 'windows-1251')) {
            return iconv('windows-1251', 'utf-8', $text);
        }
        return $text;
    }
}
