<?php

declare(strict_types=1);

namespace Iodev\Whois\Tool;

class DateTool
{
    public function parseDate(string $datestamp, bool $inverseMMDD = false): int
    {
        $stamp = $this->normalizeDateStamp($datestamp, $inverseMMDD);
        return (int)strtotime($stamp);
    }

    public function normalizeDateStamp(string $datestamp, bool $inverseMMDD = false): string
    {
        $s = trim($datestamp);
        if (preg_match('/^\d{2}[-\s]+\w+[-\s]+\d{4}[-\s]+\d{2}:\d{2}(:\d{2})?([-\s]+\w+)?/ui', $s)) {
            return $s;
        }
        if (preg_match('/^(\d{4})\.\s*(\d{2})\.\s*(\d{2})\.?\s*$/ui', $s, $m)) {
            return sprintf('%s-%s-%sT00:00:00', $m[1], $m[2], $m[3]);
        }
        if (preg_match('/^\d{4}\.\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2}/ui', $s)) {
            return str_replace(".", "-", $s);
        }
        if (preg_match('/^(\d{2})-(\w+)-(\d{4})\s+(\d{2}:\d{2}:\d{2})/ui', $s, $m)) {
            return sprintf('%s-%s-%sT%s', $m[3], $this->textMonthToDigital($m[2]), $m[1], $m[4]);
        }
        if (preg_match('/^(\d{2})[-\.](\d{2})[-\.](\d{4})$/ui', $s, $m)) {
            return sprintf('%s-%s-%sT00:00:00', $m[3], $m[2], $m[1]);
        }
        if (preg_match('/^(\d{2})[-\s]+(\w+)[-\s]+(\d{4})/ui', $s, $m)) {
            return sprintf('%s-%s-%sT00:00:00', $m[3], $this->textMonthToDigital($m[2]), $m[1]);
        }
        if (preg_match('/^(\d{4})(\d{2})(\d{2})$/ui', preg_replace('/\s*#.*/ui', '', $s), $m)) {
            return sprintf('%s-%s-%sT00:00:00', $m[1], $m[2], $m[3]);
        }
        if (preg_match('~^(\d{2})/(\d{2})/(\d{4})$~ui', $s, $m)) {
            return $inverseMMDD
                ? sprintf('%s-%s-%sT00:00:00', $m[3], $m[2], $m[1])
                : sprintf('%s-%s-%sT00:00:00', $m[3], $m[1], $m[2])
            ;
        }
        if (preg_match('/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+\(GMT([-+]\d+:\d{2})\)$/ui', $s, $m)) {
            return sprintf('%sT%s%s', $m[1], $m[2], $m[3]);
        }
        return $s;
    }

    public function parseDateInText(string $text): int
    {
        $stamp = $this->parseDateStampInText($text);
        return $stamp !== null ? strtotime($stamp) : 0;

    }

    public function parseDateStampInText(string $text): ?string
    {
        if (preg_match('~\b(\d{1,2})(nd|th|st)?[-\s]+([a-z]+)[-\s]+(\d{4})\b~ui', $text, $m)) {
            return sprintf('%s %s %s 00:00', $m[1], $m[3], $m[4]);
        }
        if (preg_match('~\b(\d{1,2})(nd|th|st)?[-\s]+([a-z]+)\b~ui', $text, $m)) {
            return sprintf('%s %s %s 00:00', $m[1], $m[3], date('Y'));
        }
        return null;
    }

    public function textMonthToDigital(string $month, string $default = '01'): string
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
        return $mond[strtolower($month)] ?? $default;
    }
}
