<?php

namespace Iodev\Whois;

/**
 * @property string query
 * @property string text
 * @property string host
 */
class Response extends DataObject
{
    /** @var string */
    protected $dataDefault = [
        'query' => '',
        'text' => '',
        'host' => '',
    ];
}
