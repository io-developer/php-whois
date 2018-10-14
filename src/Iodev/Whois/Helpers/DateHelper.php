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
        if (preg_match('/^\d{2}[-\s]+\w+[-\s]+\d{4}[-\s]+\d{2}:\d{2}(:\d{2})?([-\s]+\w+)?/ui', $s)) {
            return (int)strtotime($s);
        }
        if (preg_match('/^(\d{4})\.\s*(\d{2})\.\s*(\d{2})\.?\s*$/ui', $s, $m)) {
            $s = "{$m[1]}-{$m[2]}-{$m[3]}T00:00:00";
        } elseif (preg_match('/^\d{4}\.\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2}/ui', $s)) {
            $s = str_replace(".", "-", $s);
        } elseif (preg_match('/^(\d{2})-(\w+)-(\d{4})\s+(\d{2}:\d{2}:\d{2})/ui', $s, $m)) {
            $mon = self::textMonthToDigital($m[2]);
            $s = "{$m[3]}-{$mon}-{$m[1]}T{$m[4]}";
        } elseif (preg_match('/^(\d{2})[-\.](\d{2})[-\.](\d{4})$/ui', $s, $m)) {
            $s = "{$m[3]}-{$m[2]}-{$m[1]}T00:00:00";
        } elseif (preg_match('/^(\d{2})[-\s]+(\w+)[-\s]+(\d{4})/ui', $s, $m)) {
            $mon = self::textMonthToDigital($m[2]);
            $s = "{$m[3]}-{$mon}-{$m[1]}T00:00:00";
        } elseif (preg_match('/^(\d{4})(\d{2})(\d{2})$/ui', preg_replace('/\s*#.*/ui', '', $s), $m)) {
            $s = "{$m[1]}-{$m[2]}-{$m[3]}T00:00:00";
        } elseif (preg_match('~^(\d{2})/(\d{2})/(\d{4})$~ui', $s, $m)) {
            $s = "{$m[3]}-{$m[2]}-{$m[1]}T00:00:00";
        } elseif (preg_match('/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+\(GMT([-+]\d+:\d{2})\)$/ui', $s, $m)) {
            $s = "{$m[1]}T{$m[2]}{$m[3]}";
        }
        return (int)strtotime($s);
    }

    /**
     * @param $mon
     * @return string
     */
    public static function textMonthToDigital($mon)
    {
        $mond = [
            'jan' => '01',
            'january' => '01',
            'feb' => '02',
            'february' => '02',
            'mar' => '03',
            'march' => '03',
            'apr' => '04',
            'april' => '04',
            'may' => '05',
            'jun' => '06',
            'june' => '06',
            'jul' => '07',
            'july' => '07',
            'aug' => '08',
            'august' => '08',
            'sep' => '09',
            'september' => '09',
            'oct' => '10',
            'october' => '10',
            'nov' => '11',
            'november' => '11',
            'dec' => '12',
            'december' => '12',
        ];
        return $mond[strtolower($mon)];
    }
}
