<?php

namespace Iodev\Whois;

use FakeSocketLoader;

class WhoisTestDataInfoTest  extends \PHPUnit_Framework_TestCase
{
    private static function loadTestDataInfo($domain, $filename)
    {
        $p = new ServerProvider(Server::fromDataList(Config::getServersData()));
        $l = new FakeSocketLoader();
        $l->text = \TestData::loadContent($filename);
        $w = new Whois($p, $l);
        return $w->loadInfo($domain);
    }

    private static function sort($a)
    {
        sort($a);
        return $a;
    }

    private static function assertTestData($domain, $srcTextFilename, $expectedJsonFilename)
    {
        $info = self::loadTestDataInfo($domain, $srcTextFilename);
        $expected = json_decode(\TestData::loadContent($expectedJsonFilename), true);

        self::assertNotEmpty($expected, "Failed to load/parse expected json");

        self::assertEquals(
            $expected["domainName"],
            $info->getDomainName(),
            "Domain name mismatch ($srcTextFilename)"
        );
        self::assertEquals(
            $expected["whoisServer"],
            $info->getWhoisServer(),
            "Whois server mismatch ($srcTextFilename)"
        );
        self::assertEquals(
            self::sort($expected["nameServers"]),
            self::sort($info->getNameServers()),
            "Name servers mismatch ($srcTextFilename)"
        );
        self::assertEquals(
            strtotime($expected["creationDate"]),
            $info->getCreationDate(),
            "Creation date mismatch ($srcTextFilename)"
        );
        self::assertEquals(
            strtotime($expected["expirationDate"]),
            $info->getExpirationDate(),
            "expirationDate mismatch ($srcTextFilename)"
        );
        self::assertEquals(
            self::sort($expected["states"]),
            self::sort($info->getStates()),
            "States mismatch ($srcTextFilename)"
        );
        self::assertEquals(
            $expected["owner"],
            $info->getOwner(),
            "Owner mismatch ($srcTextFilename)"
        );
        self::assertEquals(
            $expected["registrar"],
            $info->getRegistrar(),
            "Registrar mismatch ($srcTextFilename)"
        );
    }

    public function testLoadInfoRegistered()
    {
        $info = self::loadTestDataInfo("google.com", "google.com.txt");
        self::assertNotNull($info);
        self::assertInstanceOf('\Iodev\Whois\DomainInfo', $info);
    }

    public function testLoadInfoNotRegistered()
    {
        $info = $this->loadTestDataInfo("google.com", "notregistered.txt");
        self::assertNull($info);
    }

    public function testLoadInfoValidation()
    {
        $tests = [
            [ "github.io", "github.io.txt", "github.io.json" ],
            [ "google.com", "google.com.txt", "google.com.json" ],
            [ "google.com", "google.com_registrar_whois.txt", "google.com_registrar_whois.json" ],
            [ "google.ru", "google.ru.txt", "google.ru.json" ],
            [ "google.co", "google.co.txt", "google.co.json" ],
            [ "info.info", "info.info.txt", "info.info.json" ],
            [ "linux.org", "linux.org.txt", "linux.org.json" ],
            [ "speedtest.net", "speedtest.net.txt", "speedtest.net.json" ],
            [ "speedtest.net", "speedtest.net_registrar_whois.txt", "speedtest.net_registrar_whois.json" ],
            [ "xn--80a1acny.xn--p1ai", "xn--80a1acny.xn--p1ai.txt", "xn--80a1acny.xn--p1ai.json" ],
            [ "usa.gov", "usa.gov.txt", "usa.gov.json" ],
        ];

        foreach ($tests as $test) {
            list ($domain, $text, $json) = $test;
            self::assertTestData($domain, $text, $json);
        }
    }
}