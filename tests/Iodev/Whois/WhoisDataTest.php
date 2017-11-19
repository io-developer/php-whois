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
        return $w->loadDomainInfo($domain);
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

    public function testLoadDomainInfoRegistered()
    {
        $info = self::loadTestDataInfo("google.com", ".com/google.com.txt");
        self::assertNotNull($info);
        self::assertInstanceOf('\Iodev\Whois\DomainInfo', $info);
    }

    public function testLoadDomainInfoNotRegistered()
    {
        $info = $this->loadTestDataInfo("google.com", "notregistered.txt");
        self::assertNull($info);
    }

    public function testLoadDomainInfoValidation()
    {
        $tests = [
            [ "google.co", ".co/google.co.txt", ".co/google.co.json" ],
            [ "google.com", ".com/google.com.txt", ".com/google.com.json" ],
            [ "google.com", ".com/google.com_registrar_whois.txt", ".com/google.com_registrar_whois.json" ],
            [ "usa.gov", ".gov/usa.gov.txt", ".gov/usa.gov.json" ],
            [ "info.info", ".info/info.info.txt", ".info/info.info.json" ],
            [ "github.io", ".io/github.io.txt", ".io/github.io.json" ],
            [ "speedtest.net", ".net/speedtest.net.txt", ".net/speedtest.net.json" ],
            [ "speedtest.net", ".net/speedtest.net_registrar_whois.txt", ".net/speedtest.net_registrar_whois.json" ],
            [ "linux.org", ".org/linux.org.txt", ".org/linux.org.json" ],
            [ "google.ru", ".ru/google.ru.txt", ".ru/google.ru.json" ],
            [ "xn--80a1acny.xn--p1ai", ".xn--p1ai/xn--80a1acny.xn--p1ai.txt", ".xn--p1ai/xn--80a1acny.xn--p1ai.json" ],
        ];

        foreach ($tests as $test) {
            list ($domain, $text, $json) = $test;
            self::assertTestData($domain, $text, $json);
        }
    }
}