<?php

class TestData
{
    /**
     * @param $filename
     * @return string
     * @throws InvalidArgumentException
     */
    public static function loadContent($filename)
    {
        $file = __DIR__ . '/data_files/' . $filename;
        if (!file_exists($file)) {
            throw new InvalidArgumentException("File '$file' not found");
        }
        return file_get_contents($file);
    }
}