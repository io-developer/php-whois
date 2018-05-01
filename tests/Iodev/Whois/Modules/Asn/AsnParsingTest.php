<?php

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Loaders\FakeSocketLoader;
use Iodev\Whois\Whois;

class AsnParsingTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param string $filename
     * @return Whois
     */
    private static function whoisFrom($filename)
    {
        $l = new FakeSocketLoader();
        $l->text = AsnParsingData::loadContent($filename);
        return new Whois($l);
    }

    /**
     * @param string $asn
     * @param string $srcTextFilename
     * @param string $expectedJsonFilename
     * @throws ConnectionException
     */
    private static function assertTestData($asn, $srcTextFilename, $expectedJsonFilename)
    {
        $w = self::whoisFrom($srcTextFilename);
        $info = $w->loadAsnInfo($asn);

        if (empty($expectedJsonFilename)) {
            self::assertNull($info, "Loaded info should be null for empty response ($srcTextFilename)");
            return;
        }

        $expected = json_decode(AsnParsingData::loadContent($expectedJsonFilename), true);
        self::assertNotEmpty($expected, "Failed to load/parse expected json");

        self::assertNotNull($info, "Loaded info should not be null ($srcTextFilename)");

        self::assertEquals(
            $expected["asn"],
            $info->getAsn(),
            "ASN mismatch ($srcTextFilename)"
        );

        $actualRoutes = $info->getRoutes();
        $expectedRoutes = $expected['routes'];

        self::assertEquals(
            count($expectedRoutes),
            count($actualRoutes),
            "Routes count mismatch ($srcTextFilename)"
        );

        foreach ($actualRoutes as $index => $actualRoute) {
            $expectedRoute = $expectedRoutes[$index];
            self::assertEquals(
                $expectedRoute["route"],
                $actualRoute->getRoute(),
                "Route ($index) 'route' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute["route6"],
                $actualRoute->getRoute6(),
                "Route ($index) 'route6' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute["descr"],
                $actualRoute->getDescr(),
                "Route ($index) 'descr' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute["origin"],
                $actualRoute->getOrigin(),
                "Route ($index) 'origin' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute["mntBy"],
                $actualRoute->getMntBy(),
                "Route ($index) 'mntBy' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute["changed"],
                $actualRoute->getChanged(),
                "Route ($index) 'changed' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute["source"],
                $actualRoute->getSource(),
                "Route ($index) 'source' mismatch ($srcTextFilename)"
            );
        }
    }

    /**
     * @throws ConnectionException
     */
    public function testLoadAsnInfoValidation()
    {
        $tests = [
            [ "AS32934", "AS32934/whois.ripe.net.txt", null ],
            [ "AS32934", "AS32934/whois.radb.net.txt", "AS32934/whois.radb.net.json" ],

            [ "AS62041", "AS62041/whois.ripe.net.txt", "AS62041/whois.ripe.net.json" ],
            [ "AS62041", "AS62041/whois.radb.net.txt", "AS62041/whois.radb.net.json" ],
        ];

        foreach ($tests as $test) {
            list ($domain, $text, $json) = $test;
            self::assertTestData($domain, $text, $json);
        }
    }
}