<?php

namespace Iodev\Whois\Helpers;

class DateHelper
{
    /**
     * @param string $datestamp
     * @return int
     */
    public static function parseDate($datestamp)
    {
        $s = trim($datestamp);
        if (preg_match('/^\d{4}\.\d{2}\.\d{2}$/ui', $s)) {
            $s = str_replace(".", "-", $s) . " 00:00:00";
        } elseif (preg_match('/^\d{4}\.\d{2}\.\d{2}.\s+\d{2}:\d{2}:\d{2}/ui', $s)) {
            $s = str_replace(".", "-", $s);
        }
        return (int)strtotime($s);
    }
}
