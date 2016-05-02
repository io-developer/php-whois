<?php

namespace iodev\whois\helpers;

/**
 * @author Sergey Sedyshev
 */
class DateHelper
{
    /**
     * @param string $datestamp
     * @return int
     */
    public static function parseDate( $datestamp )
    {
        $s = trim($datestamp);

        if (preg_match('/^\d\d\d\d\.\d\d\.\d\d$/ui', $s)) {
            $s = str_replace(".", "-", $s) . " 00:00:00";
        } elseif (preg_match('/^\d\d\d\d\.\d\d\.\d\d.\s+\d\d:\d\d:\d\d/ui', $s)) {
            $s = str_replace(".", "-", $s);
        }

        return (int)strtotime($s);
    }
}
