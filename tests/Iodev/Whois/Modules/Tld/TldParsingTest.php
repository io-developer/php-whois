<?php

namespace Iodev\Whois\Modules\Tld;

use InvalidArgumentException;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Loaders\FakeSocketLoader;
use Iodev\Whois\Whois;

class TldParsingTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param $filename
     * @return bool|string
     */
    private static function loadContent($filename)
    {
        $file = __DIR__ . '/parsing_data/' . $filename;
        if (!file_exists($file)) {
            throw new InvalidArgumentException("File '$file' not found");
        }
        return file_get_contents($file);
    }

    /**
     * @param string $filename
     * @return Whois
     */
    private static function whoisFrom($filename)
    {
        $l = new FakeSocketLoader();
        $l->text = self::loadContent($filename);
        return new Whois($l);
    }

    /**
     * @param array $a
     * @return array
     */
    private static function sort($a)
    {
        sort($a);
        return $a;
    }

    /**
     * @param array $items
     */
    private static function assertDataItems($items)
    {
        foreach ($items as $item) {
            list ($domain, $text, $json) = $item;
            self::assertData($domain, $text, $json);
        }
    }

    /**
     * @param $domain
     * @param $srcTextFilename
     * @param $expectedJsonFilename
     */
    private static function assertData($domain, $srcTextFilename, $expectedJsonFilename = null)
    {
        $w = self::whoisFrom($srcTextFilename);
        $tld = $w->getTldModule();
        $info = $tld->loadDomainInfo($domain);

        if (empty($expectedJsonFilename)) {
            self::assertNull($info, "Loaded info should be null for free domain ($srcTextFilename)");
            self::assertTrue($tld->isDomainAvailable($domain), "Free domain should be available ($srcTextFilename)");
            return;
        }

        $expected = json_decode(self::loadContent($expectedJsonFilename), true);
        self::assertNotEmpty($expected, "Failed to load/parse expected json ($expectedJsonFilename)");

        self::assertNotNull($info, "Loaded info should not be null ($srcTextFilename)");
        self::assertFalse($tld->isDomainAvailable($domain), "Domain should not be available ($srcTextFilename)");

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


    public function test_AC()
    {
        self::assertDataItems([
            [ "free.ac", ".ac/free.txt", null ],
            [ "google.ac", ".ac/google.ac.txt", ".ac/google.ac.json" ],
        ]);
    }

    public function test_AE()
    {
        self::assertDataItems([
            [ "free.ae", ".ae/free.txt", null ],
            [ "google.ae", ".ae/google.ae.txt", ".ae/google.ae.json" ],
        ]);
    }

    public function test_AF()
    {
        self::assertDataItems([
            [ "free.af", ".af/free.txt", null ],
            [ "google.com.af", ".af/google.com.af.txt", ".af/google.com.af.json" ],
        ]);
    }

    public function test_AG()
    {
        self::assertDataItems([
            [ "free.ag", ".ag/free.txt", null ],
            [ "google.com.ag", ".ag/google.com.ag.txt", ".ag/google.com.ag.json" ],
        ]);
    }

    public function test_AI()
    {
        self::assertDataItems([
            [ "free.ai", ".ai/free.txt", null ],
            [ "google.com.ai", ".ai/google.com.ai.txt", ".ai/google.com.ai.json" ],
        ]);
    }

    public function test_AM()
    {
        self::assertDataItems([
            [ "free.am", ".am/free.txt", null ],
            // [ "google.am", ".am/google.am.txt", ".am/google.am.json" ],
        ]);
    }

    public function test_AO()
    {
        self::assertDataItems([
            [ "free.ao", ".ao/free.txt", null ],
            [ "google.it.ao", ".ao/google.it.ao.txt", ".ao/google.it.ao.json" ],
        ]);
    }

    public function test_AS()
    {
        self::assertDataItems([
            [ "free.as", ".as/free.txt", null ],
            // [ "google.as", ".as/google.as.txt", ".as/google.as.json" ],
        ]);
    }

    public function test_AT()
    {
        self::assertDataItems([
            [ "free.at", ".at/free.txt", null ],
            [ "google.at", ".at/google.at.txt", ".at/google.at.json" ],
        ]);
    }

    public function test_AU()
    {
        self::assertDataItems([
            [ "free.au", ".au/free.txt", null ],
            [ "google.com.au", ".au/google.com.au.txt", ".au/google.com.au.json" ],
        ]);
    }

    public function test_BE()
    {
        self::assertDataItems([
            [ "free.be", ".be/free.txt", null ],
            [ "google.be", ".be/google.be.txt", ".be/google.be.json" ],
            [ "youtu.be", ".be/youtu.be.txt", ".be/youtu.be.json" ],
        ]);
    }

    public function test_BG()
    {
        self::assertDataItems([
            [ "free.bg", ".bg/free.txt", null ],
            // [ "google.bg", ".bg/google.bg.txt", ".bg/google.bg.json" ],
        ]);
    }

    public function test_BI()
    {
        self::assertDataItems([
            [ "free.bi", ".bi/free.txt", null ],
            [ "google.bi", ".bi/google.bi.txt", ".bi/google.bi.json" ],
        ]);
    }

    public function test_BJ()
    {
        self::assertDataItems([
            [ "free.bj", ".bj/free.txt", null ],
            [ "google.bj", ".bj/google.bj.txt", ".bj/google.bj.json" ],
        ]);
    }

    public function test_BN()
    {
        self::assertDataItems([
            [ "free.bn", ".bn/free.txt", null ],
            // [ "google.com.bn", ".bn/google.com.bn.txt", ".bn/google.com.bn.json" ],
        ]);
    }

    public function test_BO()
    {
        self::assertDataItems([
            [ "free.bo", ".bo/free.txt", null ],
            [ "google.com.bo", ".bo/google.com.bo.txt", ".bo/google.com.bo.json" ],
        ]);
    }

    public function test_BR()
    {
        self::assertDataItems([
            [ "free.br", ".br/free.txt", null ],
            [ "google.com.br", ".br/google.com.br.txt", ".br/google.com.br.json" ],
        ]);
    }

    public function test_BW()
    {
        self::assertDataItems([
            [ "free.bw", ".bw/free.txt", null ],
            [ "google.co.bw", ".bw/google.co.bw.txt", ".bw/google.co.bw.json" ],
        ]);
    }

    public function test_BY()
    {
        self::assertDataItems([
            [ "free.by", ".by/free.txt", null ],
            [ "google.by", ".by/google.by.txt", ".by/google.by.json" ],
            [ "google.com.by", ".by/google.com.by.txt", ".by/google.com.by.json" ],
        ]);
    }

    public function test_BZ()
    {
        self::assertDataItems([
            [ "free.bz", ".bz/free.txt", null ],
            [ "google.com.bz", ".bz/google.com.bz.txt", ".bz/google.com.bz.json" ],
        ]);
    }

    public function test_CAT()
    {
        self::assertDataItems([
            [ "free.cat", ".cat/free.txt", null ],
            [ "google.cat", ".cat/google.cat.txt", ".cat/google.cat.json" ],
        ]);
    }

    public function test_CC()
    {
        self::assertDataItems([
            [ "free.cc", ".cc/free.txt", null ],
            [ "google.cc", ".cc/google.cc.txt", ".cc/google.cc.json" ],
        ]);
    }

    public function test_CF()
    {
        self::assertDataItems([
            [ "free.cf", ".cf/free.txt", null ],
            // [ "google.cf", ".cf/google.cf.txt", ".cf/google.cf.json" ],
        ]);
    }

    public function test_CI()
    {
        self::assertDataItems([
            [ "free.ci", ".ci/free.txt", null ],
            [ "google.ci", ".ci/google.ci.txt", ".ci/google.ci.json" ],
        ]);
    }

    public function test_CL()
    {
        self::assertDataItems([
            [ "free.cl", ".cl/free.txt", null ],
            // [ "google.cl", ".cl/google.cl.txt", ".cl/google.cl.json" ],
        ]);
    }

    public function test_CM()
    {
        self::assertDataItems([
            [ "free.cm", ".cm/free.txt", null ],
            [ "google.cm", ".cm/google.cm.txt", ".cm/google.cm.json" ],
        ]);
    }

    public function test_CN()
    {
        self::assertDataItems([
            [ "free.cn", ".cn/free.txt", null ],
            [ "google.cn", ".cn/google.cn.txt", ".cn/google.cn.json" ],
        ]);
    }

    public function test_CO()
    {
        self::assertDataItems([
            [ "free.co", ".co/free.txt", null ],
            [ "google.co", ".co/google.co.txt", ".co/google.co.json" ],
            [ "google.com.co", ".co/google.com.co.txt", ".co/google.com.co.json" ],
        ]);
    }

    public function test_COM()
    {
        self::assertDataItems([
            [ "free.com", ".com/free.txt", null ],
            [ "google.com", ".com/google.com.txt", ".com/google.com.json" ],
            [ "google.com", ".com/google.com_registrar_whois.txt", ".com/google.com_registrar_whois.json" ],
        ]);
    }

    public function test_CR()
    {
        self::assertDataItems([
            [ "free.cr", ".cr/free.txt", null ],
            [ "google.co.cr", ".cr/google.co.cr.txt", ".cr/google.co.cr.json" ],
        ]);
    }

    public function test_CZ()
    {
        self::assertDataItems([
            [ "free.cz", ".cz/free.txt", null ],
            [ "google.cz", ".cz/google.cz.txt", ".cz/google.cz.json" ],
        ]);
    }

    public function test_DE()
    {
        self::assertDataItems([
            [ "free.de", ".de/free.txt", null ],
            [ "google.de", ".de/google.de.txt", ".de/google.de.json" ],
        ]);
    }

    public function test_DK()
    {
        self::assertDataItems([
            [ "free.dk", ".dk/free.txt", null ],
            [ "google.dk", ".dk/google.dk.txt", ".dk/google.dk.json" ],
        ]);
    }

    public function test_DM()
    {
        self::assertDataItems([
            [ "free.dm", ".dm/free.txt", null ],
            [ "google.dm", ".dm/google.dm.txt", ".dm/google.dm.json" ],
        ]);
    }

    public function test_DO()
    {
        self::assertDataItems([
            [ "free.do", ".do/free.txt", null ],
            [ "google.com.do", ".do/google.com.do.txt", ".do/google.com.do.json" ],
        ]);
    }

    public function test_DZ()
    {
        self::assertDataItems([
            [ "free.dz", ".dz/free.txt", null ],
            [ "google.dz", ".dz/google.dz.txt", ".dz/google.dz.json" ],
        ]);
    }

    public function test_EC()
    {
        self::assertDataItems([
            [ "free.ec", ".ec/free.txt", null ],
            // [ "google.com.ec", ".ec/google.com.ec.txt", ".ec/google.com.ec.json" ],
        ]);
    }

    public function test_EE()
    {
        self::assertDataItems([
            [ "free.ee", ".ee/free.txt", null ],
            [ "google.ee", ".ee/google.ee.txt", ".ee/google.ee.json" ],
        ]);
    }

    public function test_EU()
    {
        self::assertDataItems([
            [ "dsfasdfasdfsdafasfasfas.eu", ".eu/free.txt", null ],
            [ "google.eu", ".eu/google.eu.txt", ".eu/google.eu.json" ],
        ]);
    }

    public function test_FI()
    {
        self::assertDataItems([
            [ "free.fi", ".fi/free.txt", null ],
            [ "google.fi", ".fi/google.fi.txt", ".fi/google.fi.json" ],
            [ "xn--sisministeri-icb5x.fi", ".fi/xn--sisministeri-icb5x.fi.txt", ".fi/xn--sisministeri-icb5x.fi.json" ],
            [ "sisäministeriö.fi", ".fi/xn--sisministeri-icb5x.fi.txt", ".fi/xn--sisministeri-icb5x.fi.json" ],
        ]);
    }

    public function test_FJ()
    {
        self::assertDataItems([
            [ "free.fj", ".fj/free.txt", null ],
            // [ "google.com.fj", ".fj/google.com.fj.txt", ".fj/google.com.fj.json" ],
        ]);
    }

    public function test_FM()
    {
        self::assertDataItems([
            [ "free.fm", ".fm/free.txt", null ],
            [ "google.fm", ".fm/google.fm.txt", ".fm/google.fm.json" ],
        ]);
    }

    public function test_FR()
    {
        self::assertDataItems([
            [ "free.fr", ".fr/free.txt", null ],
            [ "google.fr", ".fr/google.fr.txt", ".fr/google.fr.json" ],
        ]);
    }

    public function test_GA()
    {
        self::assertDataItems([
            [ "free.ga", ".ga/free.txt", null ],
            // [ "google.ga", ".ga/google.ga.txt", ".ga/google.ga.json" ],
        ]);
    }

    public function test_GD()
    {
        self::assertDataItems([
            [ "free.gd", ".gd/free.txt", null ],
            [ "google.gd", ".gd/google.gd.txt", ".gd/google.gd.json" ],
        ]);
    }

    public function test_GF()
    {
        self::assertDataItems([
            [ "free.gf", ".gf/free.txt", null ],
            // [ "google.gf", ".gf/google.gf.txt", ".gf/google.gf.json" ],
        ]);
    }

    public function test_GG()
    {
        self::assertDataItems([
            [ "free.gg", ".gg/free.txt", null ],
            // [ "google.gg", ".gg/google.gg.txt", ".gg/google.gg.json" ],
        ]);
    }

    public function test_GI()
    {
        self::assertDataItems([
            [ "free.gi", ".gi/free.txt", null ],
            [ "google.com.gi", ".gi/google.com.gi.txt", ".gi/google.com.gi.json" ],
        ]);
    }

    public function test_GL()
    {
        self::assertDataItems([
            [ "free.gl", ".gl/free.txt", null ],
            [ "google.gl", ".gl/google.gl.txt", ".gl/google.gl.json" ],
        ]);
    }

    public function test_GOV()
    {
        self::assertDataItems([
            [ "free.gov", ".gov/free.txt", null ],
            [ "usa.gov", ".gov/usa.gov.txt", ".gov/usa.gov.json" ],
        ]);
    }

    public function test_GY()
    {
        self::assertDataItems([
            [ "free.gy", ".gy/free.txt", null ],
            [ "google.gy", ".gy/google.gy.txt", ".gy/google.gy.json" ],
        ]);
    }

    public function test_HK()
    {
        self::assertDataItems([
            [ "free.hk", ".hk/free.txt", null ],
            // [ "google.com.hk", ".hk/google.com.hk.txt", ".hk/google.com.hk.json" ],
        ]);
    }

    public function test_HR()
    {
        self::assertDataItems([
            [ "free.hr", ".hr/free.txt", null ],
            [ "google.hr", ".hr/google.hr.txt", ".hr/google.hr.json" ],
        ]);
    }

    public function test_HT()
    {
        self::assertDataItems([
            [ "free.ht", ".ht/free.txt", null ],
            [ "google.ht", ".ht/google.ht.txt", ".ht/google.ht.json" ],
        ]);
    }

    public function test_HU()
    {
        self::assertDataItems([
            [ "free.hu", ".hu/free.txt", null ],
            [ "google.hu", ".hu/google.hu.txt", ".hu/google.hu.json" ],
        ]);
    }

    public function test_ID()
    {
        self::assertDataItems([
            [ "free.id", ".id/free.txt", null ],
            [ "google.co.id", ".id/google.co.id.txt", ".id/google.co.id.json" ],
        ]);
    }

    public function test_IE()
    {
        self::assertDataItems([
            [ "free.ie", ".ie/free.txt", null ],
            [ "google.ie", ".ie/google.ie.txt", ".ie/google.ie.json" ],
        ]);
    }

    public function test_IL()
    {
        self::assertDataItems([
            [ "free.il", ".il/free.txt", null ],
            [ "google.co.il", ".il/google.co.il.txt", ".il/google.co.il.json" ],
        ]);
    }

    public function test_IM()
    {
        self::assertDataItems([
            [ "free.im", ".im/free.txt", null ],
            // [ "google.im", ".im/google.im.txt", ".im/google.im.json" ],
        ]);
    }

    public function test_IN()
    {
        self::assertDataItems([
            [ "free.in", ".in/free.txt", null ],
            [ "google.co.in", ".in/google.co.in.txt", ".in/google.co.in.json" ],
        ]);
    }

    public function test_INFO()
    {
        self::assertDataItems([
            [ "free.info", ".info/free.txt", null ],
            [ "info.info", ".info/info.info.txt", ".info/info.info.json" ],
        ]);
    }

    public function test_IO()
    {
        self::assertDataItems([
            [ "free.io", ".io/free.txt", null ],
            [ "github.io", ".io/github.io.txt", ".io/github.io.json" ],
            [ "google.io", ".io/google.io.txt", ".io/google.io.json" ],
            [ "codepen.io", ".io/codepen.io.txt", ".io/codepen.io.json" ],
        ]);
    }

    public function test_IQ()
    {
        self::assertDataItems([
            [ "free.iq", ".iq/free.txt", null ],
            [ "google.iq", ".iq/google.iq.txt", ".iq/google.iq.json" ],
        ]);
    }

    public function test_IS()
    {
        self::assertDataItems([
            [ "free.is", ".is/free.txt", null ],
            [ "google.is", ".is/google.is.txt", ".is/google.is.json" ],
        ]);
    }

    public function test_IT()
    {
        self::assertDataItems([
            [ "free.it", ".it/free.txt", null ],
            [ "google.it", ".it/google.it.txt", ".it/google.it.json" ],
            [ "nintendo.it", ".it/nintendo.it.txt", ".it/nintendo.it.json" ],
        ]);
    }

    public function test_JE()
    {
        self::assertDataItems([
            [ "free.je", ".je/free.txt", null ],
            // [ "google.je", ".je/google.je.txt", ".je/google.je.json" ],
        ]);
    }

    public function test_JP()
    {
        self::assertDataItems([
            [ "free.jp", ".jp/free.txt", null ],
            // [ "google.co.jp", ".jp/google.co.jp.txt", ".jp/google.co.jp.json" ],
        ]);
    }

    public function test_KG()
    {
        self::assertDataItems([
            [ "free.kg", ".kg/free.txt", null ],
            // [ "google.kg", ".kg/google.kg.txt", ".kg/google.kg.json" ],
        ]);
    }

    public function test_KI()
    {
        self::assertDataItems([
            [ "free.ki", ".ki/free.txt", null ],
            [ "google.ki", ".ki/google.ki.txt", ".ki/google.ki.json" ],
        ]);
    }

    public function test_KR()
    {
        self::assertDataItems([
            [ "free.kr", ".kr/free.txt", null ],
            [ "google.co.kr", ".kr/google.co.kr.txt", ".kr/google.co.kr.json" ],
        ]);
    }

    public function test_KZ()
    {
        self::assertDataItems([
            [ "free.kz", ".kz/free.txt", null ],
            [ "google.kz", ".kz/google.kz.txt", ".kz/google.kz.json" ],
        ]);
    }

    public function test_LA()
    {
        self::assertDataItems([
            [ "free.la", ".la/free.txt", null ],
            [ "google.la", ".la/google.la.txt", ".la/google.la.json" ],
        ]);
    }

    public function test_LC()
    {
        self::assertDataItems([
            [ "free.lc", ".lc/free.txt", null ],
            [ "google.com.lc", ".lc/google.com.lc.txt", ".lc/google.com.lc.json" ],
        ]);
    }

    public function test_LT()
    {
        self::assertDataItems([
            [ "free.lt", ".lt/free.txt", null ],
            [ "google.lt", ".lt/google.lt.txt", ".lt/google.lt.json" ],
        ]);
    }

    public function test_LU()
    {
        self::assertDataItems([
            [ "free.lu", ".lu/free.txt", null ],
            [ "google.lu", ".lu/google.lu.txt", ".lu/google.lu.json" ],
        ]);
    }

    public function test_LV()
    {
        self::assertDataItems([
            [ "free.lv", ".lv/free.txt", null ],
            [ "google.lv", ".lv/google.lv.txt", ".lv/google.lv.json" ],
        ]);
    }

    public function test_LY()
    {
        self::assertDataItems([
            [ "free.ly", ".ly/free.txt", null ],
            // [ "google.com.ly", ".ly/google.com.ly.txt", ".ly/google.com.ly.json" ],
        ]);
    }

    public function test_MA()
    {
        self::assertDataItems([
            [ "free.ma", ".ma/free.txt", null ],
            [ "google.co.ma", ".ma/google.co.ma.txt", ".ma/google.co.ma.json" ],
        ]);
    }

    public function test_MD()
    {
        self::assertDataItems([
            [ "free.md", ".md/free.txt", null ],
            [ "google.md", ".md/google.md.txt", ".md/google.md.json" ],
        ]);
    }

    public function test_ME()
    {
        self::assertDataItems([
            [ "free.me", ".me/free.txt", null ],
            [ "google.me", ".me/google.me.txt", ".me/google.me.json" ],
        ]);
    }

    public function test_MG()
    {
        self::assertDataItems([
            [ "free.mg", ".mg/free.txt", null ],
            [ "google.mg", ".mg/google.mg.txt", ".mg/google.mg.json" ],
        ]);
    }

    public function test_MK()
    {
        self::assertDataItems([
            [ "free.mk", ".mk/free.txt", null ],
            [ "google.mk", ".mk/google.mk.txt", ".mk/google.mk.json" ],
        ]);
    }

    public function test_ML()
    {
        self::assertDataItems([
            [ "free.ml", ".ml/free.txt", null ],
            // [ "google.ml", ".ml/google.ml.txt", ".ml/google.ml.json" ],
        ]);
    }

    public function test_MN()
    {
        self::assertDataItems([
            [ "free.mn", ".mn/free.txt", null ],
            [ "google.mn", ".mn/google.mn.txt", ".mn/google.mn.json" ],
        ]);
    }

    public function test_MS()
    {
        self::assertDataItems([
            [ "free.ms", ".ms/free.txt", null ],
            [ "google.ms", ".ms/google.ms.txt", ".ms/google.ms.json" ],
        ]);
    }

    public function test_MU()
    {
        self::assertDataItems([
            [ "free.mu", ".mu/free.txt", null ],
            [ "google.mu", ".mu/google.mu.txt", ".mu/google.mu.json" ],
        ]);
    }

    public function test_MX()
    {
        self::assertDataItems([
            [ "free.mx", ".mx/free.txt", null ],
            // [ "google.com.mx", ".mx/google.com.mx.txt", ".mx/google.com.mx.json" ],
        ]);
    }

    public function test_MZ()
    {
        self::assertDataItems([
            [ "free.mz", ".mz/free.txt", null ],
            [ "google.co.mz", ".mz/google.co.mz.txt", ".mz/google.co.mz.json" ],
        ]);
    }

    public function test_NA()
    {
        self::assertDataItems([
            [ "free.na", ".na/free.txt", null ],
            [ "google.com.na", ".na/google.com.na.txt", ".na/google.com.na.json" ],
        ]);
    }

    public function test_NET()
    {
        self::assertDataItems([
            [ "free.net", ".net/free.txt", null ],
            [ "speedtest.net", ".net/speedtest.net.txt", ".net/speedtest.net.json" ],
            [ "speedtest.net", ".net/speedtest.net_registrar_whois.txt", ".net/speedtest.net_registrar_whois.json" ],
        ]);
    }

    public function test_NF()
    {
        self::assertDataItems([
            [ "free.nf", ".nf/free.txt", null ],
            [ "google.com.nf", ".nf/google.com.nf.txt", ".nf/google.com.nf.json" ],
        ]);
    }

    public function test_NG()
    {
        self::assertDataItems([
            [ "free.ng", ".ng/free.txt", null ],
            [ "google.com.ng", ".ng/google.com.ng.txt", ".ng/google.com.ng.json" ],
        ]);
    }

    public function test_NL()
    {
        self::assertDataItems([
            [ "free.nl", ".nl/free.txt", null ],
            // [ "google.nl", ".nl/google.nl.txt", ".nl/google.nl.json" ],
        ]);
    }

    public function test_NO()
    {
        self::assertDataItems([
            [ "free.no", ".no/free.txt", null ],
            [ "google.no", ".no/google.no.txt", ".no/google.no.json" ],
        ]);
    }

    public function test_NU()
    {
        self::assertDataItems([
            [ "free.nu", ".nu/free.txt", null ],
            [ "google.nu", ".nu/google.nu.txt", ".nu/google.nu.json" ],
        ]);
    }

    public function test_NZ()
    {
        self::assertDataItems([
            [ "free.nz", ".nz/free.txt", null ],
            [ "progressbuilders.co.nz.nz", ".nz/free_progressbuilders.co.nz.nz.txt", null ],
            [ "secuirty-services.co.nz", ".nz/free_secuirty-services.co.nz.txt", null ],
            [ "google.co.nz", ".nz/google.co.nz.txt", ".nz/google.co.nz.json" ],
            [ "payrollmatters.co.nz", ".nz/payrollmatters.co.nz.txt", ".nz/payrollmatters.co.nz.json" ],
            [ "smarttech.nz", ".nz/smarttech.nz.txt", ".nz/smarttech.nz.json" ],
        ]);
    }

    public function test_ORG()
    {
        self::assertDataItems([
            [ "free.org", ".org/free.txt", null ],
            [ "linux.org", ".org/linux.org.txt", ".org/linux.org.json" ],
        ]);
    }

    public function test_OM()
    {
        self::assertDataItems([
            [ "free.om", ".om/free.txt", null ],
            [ "google.com.om", ".om/google.com.om.txt", ".om/google.com.om.json" ],
        ]);
    }

    public function test_PE()
    {
        self::assertDataItems([
            [ "free.pe", ".pe/free.txt", null ],
            [ "google.com.pe", ".pe/google.com.pe.txt", ".pe/google.com.pe.json" ],
        ]);
    }

    public function test_PL()
    {
        self::assertDataItems([
            [ "free.pl", ".pl/free.txt", null ],
            [ "google.pl", ".pl/google.pl.txt", ".pl/google.pl.json" ],
        ]);
    }

    public function test_PR()
    {
        self::assertDataItems([
            [ "free.pr", ".pr/free.txt", null ],
            [ "google.com.pr", ".pr/google.com.pr.txt", ".pr/google.com.pr.json" ],
        ]);
    }

    public function test_PS()
    {
        self::assertDataItems([
            [ "free.ps", ".ps/free.txt", null ],
            [ "google.ps", ".ps/google.ps.txt", ".ps/google.ps.json" ],
        ]);
    }

    public function test_QA()
    {
        self::assertDataItems([
            [ "free.qa", ".qa/free.txt", null ],
            [ "google.com.qa", ".qa/google.com.qa.txt", ".qa/google.com.qa.json" ],
        ]);
    }

    public function test_RO()
    {
        self::assertDataItems([
            [ "free.ro", ".ro/free.txt", null ],
            [ "google.ro", ".ro/google.ro.txt", ".ro/google.ro.json" ],
            [ "rotld.ro", ".ro/rotld.ro.txt", ".ro/rotld.ro.json" ],
            [ "anaf.ro", ".ro/anaf.ro.txt", ".ro/anaf.ro.json" ],
        ]);
    }

    public function test_RS()
    {
        self::assertDataItems([
            [ "free.rs", ".rs/free.txt", null ],
            [ "google.rs", ".rs/google.rs.txt", ".rs/google.rs.json" ],
        ]);
    }

    public function test_RU()
    {
        self::assertDataItems([
            [ "free.ru", ".ru/free.txt", null ],
            [ "google.ru", ".ru/google.ru.txt", ".ru/google.ru.json" ],
        ]);
    }

    public function test_RW()
    {
        self::assertDataItems([
            [ "free.rw", ".rw/free.txt", null ],
            [ "google.rw", ".rw/google.rw.txt", ".rw/google.rw.json" ],
        ]);
    }

    public function test_SA()
    {
        self::assertDataItems([
            [ "free.sa", ".sa/free.txt", null ],
            // [ "google.com.sa", ".sa/google.com.sa.txt", ".sa/google.com.sa.json" ],
        ]);
    }

    public function test_SB()
    {
        self::assertDataItems([
            [ "free.sb", ".sb/free.txt", null ],
            [ "google.com.sb", ".sb/google.com.sb.txt", ".sb/google.com.sb.json" ],
        ]);
    }

    public function test_SC()
    {
        self::assertDataItems([
            [ "free.sc", ".sc/free.txt", null ],
            [ "google.sc", ".sc/google.sc.txt", ".sc/google.sc.json" ],
        ]);
    }

    public function test_SE()
    {
        self::assertDataItems([
            [ "free.se", ".se/free.txt", null ],
            [ "google.se", ".se/google.se.txt", ".se/google.se.json" ],
        ]);
    }

    public function test_SG()
    {
        self::assertDataItems([
            [ "free.sg", ".sg/free.txt", null ],
            // [ "google.com.sg", ".sg/google.com.sg.txt", ".sg/google.com.sg.json" ],
        ]);
    }

    public function test_SH()
    {
        self::assertDataItems([
            [ "free.sh", ".sh/free.txt", null ],
            [ "google.sh", ".sh/google.sh.txt", ".sh/google.sh.json" ],
        ]);
    }

    public function test_SI()
    {
        self::assertDataItems([
            [ "free.si", ".si/free.txt", null ],
            [ "google.si", ".si/google.si.txt", ".si/google.si.json" ],
        ]);
    }

    public function test_SK()
    {
        self::assertDataItems([
            [ "free.sk", ".sk/free.txt", null ],
            [ "google.sk", ".sk/google.sk.txt", ".sk/google.sk.json" ],
        ]);
    }

    public function test_SL()
    {
        self::assertDataItems([
            [ "free.sl", ".sl/free.txt", null ],
            [ "google.com.sl", ".sl/google.com.sl.txt", ".sl/google.com.sl.json" ],
        ]);
    }

    public function test_SM()
    {
        self::assertDataItems([
            [ "free.sm", ".sm/free.txt", null ],
            // [ "google.sm", ".sm/google.sm.txt", ".sm/google.sm.json" ],
        ]);
    }

    public function test_SN()
    {
        self::assertDataItems([
            [ "free.sn", ".sn/free.txt", null ],
            // [ "google.sn", ".sn/google.sn.txt", ".sn/google.sn.json" ],
        ]);
    }

    public function test_SO()
    {
        self::assertDataItems([
            [ "free.so", ".so/free.txt", null ],
            [ "google.so", ".so/google.so.txt", ".so/google.so.json" ],
        ]);
    }

    public function test_ST()
    {
        self::assertDataItems([
            [ "free.st", ".st/free.txt", null ],
            [ "google.st", ".st/google.st.txt", ".st/google.st.json" ],
        ]);
    }

    public function test_TG()
    {
        self::assertDataItems([
            [ "free.tg", ".tg/free.txt", null ],
            [ "google.tg", ".tg/google.tg.txt", ".tg/google.tg.json" ],
        ]);
    }

    public function test_TH()
    {
        self::assertDataItems([
            [ "free.th", ".th/free.txt", null ],
            [ "google.co.th", ".th/google.co.th.txt", ".th/google.co.th.json" ],
        ]);
    }

    public function test_TK()
    {
        self::assertDataItems([
            [ "free.tk", ".tk/free.txt", null ],
            // [ "google.tk", ".tk/google.tk.txt", ".tk/google.tk.json" ],
        ]);
    }

    public function test_TL()
    {
        self::assertDataItems([
            [ "free.tl", ".tl/free.txt", null ],
            [ "google.tl", ".tl/google.tl.txt", ".tl/google.tl.json" ],
        ]);
    }

    public function test_TM()
    {
        self::assertDataItems([
            [ "free.tm", ".tm/free.txt", null ],
            [ "google.tm", ".tm/google.tm.txt", ".tm/google.tm.json" ],
        ]);
    }

    public function test_TN()
    {
        self::assertDataItems([
            [ "free.tn", ".tn/free.txt", null ],
            [ "google.com.tn", ".tn/google.com.tn.txt", ".tn/google.com.tn.json" ],
        ]);
    }

    public function test_TO()
    {
        self::assertDataItems([
            [ "free.to", ".to/free.txt", null ],
            // [ "google.to", ".to/google.to.txt", ".to/google.to.json" ],
        ]);
    }

    public function test_TR()
    {
        self::assertDataItems([
            [ "free.tr", ".tr/free.txt", null ],
            // [ "google.com.tr", ".tr/google.com.tr.txt", ".tr/google.com.tr.json" ],
        ]);
    }

    public function test_TW()
    {
        self::assertDataItems([
            [ "free.tw", ".tw/free.txt", null ],
            // [ "google.com.tw", ".tw/google.com.tw.txt", ".tw/google.com.tw.json" ],
        ]);
    }

    public function test_TZ()
    {
        self::assertDataItems([
            [ "free.tz", ".tz/free.txt", null ],
            [ "google.co.tz", ".tz/google.co.tz.txt", ".tz/google.co.tz.json" ],
        ]);
    }

    public function test_UA()
    {
        self::assertDataItems([
            [ "free.ua", ".ua/free.txt", null ],
            [ "google.com.ua", ".ua/google.com.ua.txt", ".ua/google.com.ua.json" ],
        ]);
    }

    public function test_UK()
    {
        self::assertDataItems([
            [ "free.uk", ".uk/free.txt", null ],
            [ "google.co.uk", ".uk/google.co.uk.txt", ".uk/google.co.uk.json" ],
        ]);
    }

    public function test_US()
    {
        self::assertDataItems([
            [ "free.us", ".us/free.txt", null ],
            [ "google.us", ".us/google.us.txt", ".us/google.us.json" ],
        ]);
    }

    public function test_UY()
    {
        self::assertDataItems([
            [ "free.uy", ".uy/free.txt", null ],
            // [ "google.uy", ".uy/google.uy.txt", ".uy/google.uy.json" ],
        ]);
    }

    public function test_UZ()
    {
        self::assertDataItems([
            [ "free.uz", ".uz/free.txt", null ],
            [ "google.uz", ".uz/google.uz.txt", ".uz/google.uz.json" ],
        ]);
    }

    public function test_VC()
    {
        self::assertDataItems([
            [ "free.vc", ".vc/free.txt", null ],
            [ "google.com.vc", ".vc/google.com.vc.txt", ".vc/google.com.vc.json" ],
        ]);
    }

    public function test_VE()
    {
        self::assertDataItems([
            [ "free.ve", ".ve/free.txt", null ],
            // [ "google.co.ve", ".ve/google.co.ve.txt", ".ve/google.co.ve.json" ],
        ]);
    }

    public function test_VG()
    {
        self::assertDataItems([
            [ "free.vg", ".vg/free.txt", null ],
            [ "google.vg", ".vg/google.vg.txt", ".vg/google.vg.json" ],
        ]);
    }

    public function test_VU()
    {
        self::assertDataItems([
            [ "free.vu", ".vu/free.txt", null ],
            // [ "google.vu", ".vu/google.vu.txt", ".vu/google.vu.json" ],
        ]);
    }

    public function test_WS()
    {
        self::assertDataItems([
            [ "free.ws", ".ws/free.txt", null ],
            [ "google.ws", ".ws/google.ws.txt", ".ws/google.ws.json" ],
        ]);
    }

    public function test_ZM()
    {
        self::assertDataItems([
            [ "free.zm", ".zm/free.txt", null ],
            [ "google.co.zm", ".zm/google.co.zm.txt", ".zm/google.co.zm.json" ],
        ]);
    }

    public function test_XN__P1AI()
    {
        self::assertDataItems([
            // .рф
            [ "free.xn--p1ai", ".xn--p1ai/free.txt", null ],
            [ "xn--80a1acny.xn--p1ai", ".xn--p1ai/xn--80a1acny.xn--p1ai.txt", ".xn--p1ai/xn--80a1acny.xn--p1ai.json" ],
        ]);
    }
}