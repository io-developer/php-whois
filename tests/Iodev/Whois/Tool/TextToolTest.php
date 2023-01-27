<?php

declare(strict_types=1);

namespace Iodev\Whois\Tool;

use InvalidArgumentException;
use Iodev\Whois\BaseTestCase;

class TextToolTest extends BaseTestCase
{
    protected TextTool $textTool;

    protected function onConstructed()
    {
        $this->textTool = new TextTool();
    }

    protected function loadContent(string $filename): mixed
    {
        $file = __DIR__ . '/text_data/' . $filename;
        if (!file_exists($file)) {
            throw new InvalidArgumentException("File '$file' not found");
        }
        return file_get_contents($file);
    }

    public function getToUtf8Data(): array
    {
        return [
            ['encoding.fin.in.txt', 'encoding.fin.out.txt'],
            ['encoding.ukr.in.txt', 'encoding.ukr.out.txt'],
        ];
    }

    /**
     * @dataProvider getToUtf8Data
     */
    public function testToUtf8(string $inputFile, string $outputFile): void
    {
        $input = $this->loadContent($inputFile);
        $inpuUtf8 = $this->textTool->toUtf8($input);
        $inpuUtf8Normalized = preg_replace('~\r\n|\r|\n~ui', '\n', $inpuUtf8);

        $output = $this->loadContent($outputFile);
        $outputNormalized = preg_replace('~\r\n|\r|\n~ui', '\n', $output);

        self::assertEquals($outputNormalized, $inpuUtf8Normalized);
    }
}
