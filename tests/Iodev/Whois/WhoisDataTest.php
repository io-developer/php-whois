<?php

namespace Iodev\Whois;

use FakeSocketLoader;

class WhoisTestDataInfoTest  extends \PHPUnit_Framework_TestCase
{
    private static function whoisFrom($filename)
    {
        $dataList = array_merge(Config::getServersData(), []);
        $p = new ServerProvider(Server::fromDataList($dataList));
        $l = new FakeSocketLoader();
        $l->text = \TestData::loadContent($filename);
        $w = new Whois($p, $l);
        return $w;
    }

    private static function sort($a)
    {
        sort($a);
        return $a;
    }

    private static function assertTestData($domain, $srcTextFilename, $expectedJsonFilename)
    {
        $w = self::whoisFrom($srcTextFilename);
        $info = $w->loadDomainInfo($domain);

        if (empty($expectedJsonFilename)) {
            self::assertNull($info, "Loaded info should be null for free domain ($srcTextFilename)");
            self::assertTrue($w->isDomainAvailable($domain), "Free domain should be available ($srcTextFilename)");
            return;
        }

        $expected = json_decode(\TestData::loadContent($expectedJsonFilename), true);
        self::assertNotEmpty($expected, "Failed to load/parse expected json");

        self::assertNotNull($info, "Loaded info should not be null ($srcTextFilename)");
        self::assertFalse($w->isDomainAvailable($domain), "Domain should not be available ($srcTextFilename)");

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

    public function testLoadDomainInfoValidation()
    {
        $tests = [

            [ "free.ac", ".ac/free.txt", null ],
            [ "google.ac", ".ac/google.ac.txt", ".ac/google.ac.json" ],

            [ "free.ae", ".ae/free.txt", null ],
            [ "google.ae", ".ae/google.ae.txt", ".ae/google.ae.json" ],

            [ "free.af", ".af/free.txt", null ],
            [ "google.com.af", ".af/google.com.af.txt", ".af/google.com.af.json" ],

            [ "free.ag", ".ag/free.txt", null ],
            [ "google.com.ag", ".ag/google.com.ag.txt", ".ag/google.com.ag.json" ],

            [ "free.ai", ".ai/free.txt", null ],
            // [ "google.com.ai", ".ai/google.com.ai.txt", ".ai/google.com.ai.json" ],

            [ "free.am", ".am/free.txt", null ],
            // [ "google.am", ".am/google.am.txt", ".am/google.am.json" ],

            [ "free.ao", ".ao/free.txt", null ],
            [ "google.it.ao", ".ao/google.it.ao.txt", ".ao/google.it.ao.json" ],

            [ "free.as", ".as/free.txt", null ],
            // [ "google.as", ".as/google.as.txt", ".as/google.as.json" ],

            [ "free.at", ".at/free.txt", null ],
            [ "google.at", ".at/google.at.txt", ".at/google.at.json" ],

            [ "free.au", ".au/free.txt", null ],
            [ "google.com.au", ".au/google.com.au.txt", ".au/google.com.au.json" ],

            [ "free.be", ".be/free.txt", null ],
            // [ "google.be", ".be/google.be.txt", ".be/google.be.json" ],

            [ "free.bg", ".bg/free.txt", null ],
            // [ "google.bg", ".bg/google.bg.txt", ".bg/google.bg.json" ],

            [ "free.bi", ".bi/free.txt", null ],
            [ "google.bi", ".bi/google.bi.txt", ".bi/google.bi.json" ],

            [ "free.bj", ".bj/free.txt", null ],
            [ "google.bj", ".bj/google.bj.txt", ".bj/google.bj.json" ],

            [ "free.bn", ".bn/free.txt", null ],
            // [ "google.com.bn", ".bn/google.com.bn.txt", ".bn/google.com.bn.json" ],

            [ "free.bo", ".bo/free.txt", null ],
            // [ "google.com.bo", ".bo/google.com.bo.txt", ".bo/google.com.bo.json" ],

            [ "free.br", ".br/free.txt", null ],
            // [ "google.com.br", ".br/google.com.br.txt", ".br/google.com.br.json" ],

            [ "free.bw", ".bw/free.txt", null ],
            [ "google.co.bw", ".bw/google.co.bw.txt", ".bw/google.co.bw.json" ],

            [ "free.by", ".by/free.txt", null ],
            [ "google.com.by", ".by/google.com.by.txt", ".by/google.com.by.json" ],

            [ "free.by", ".by/free.txt", null ],
            [ "google.by", ".by/google.by.txt", ".by/google.by.json" ],

            [ "free.bz", ".bz/free.txt", null ],
            [ "google.com.bz", ".bz/google.com.bz.txt", ".bz/google.com.bz.json" ],

            [ "free.cat", ".cat/free.txt", null ],
            [ "google.cat", ".cat/google.cat.txt", ".cat/google.cat.json" ],

            [ "free.cc", ".cc/free.txt", null ],
            [ "google.cc", ".cc/google.cc.txt", ".cc/google.cc.json" ],

            [ "free.cf", ".cf/free.txt", null ],
            // [ "google.cf", ".cf/google.cf.txt", ".cf/google.cf.json" ],

            [ "free.ci", ".ci/free.txt", null ],
            [ "google.ci", ".ci/google.ci.txt", ".ci/google.ci.json" ],

            [ "free.cl", ".cl/free.txt", null ],
            // [ "google.cl", ".cl/google.cl.txt", ".cl/google.cl.json" ],

            [ "free.cm", ".cm/free.txt", null ],
            // [ "google.cm", ".cm/google.cm.txt", ".cm/google.cm.json" ],

            [ "free.cn", ".cn/free.txt", null ],
            [ "google.cn", ".cn/google.cn.txt", ".cn/google.cn.json" ],

            [ "free.co", ".co/free.txt", null ],
            [ "google.co", ".co/google.co.txt", ".co/google.co.json" ],
            [ "google.com.co", ".co/google.com.co.txt", ".co/google.com.co.json" ],

            [ "free.com", ".com/free.txt", null ],
            [ "google.com", ".com/google.com.txt", ".com/google.com.json" ],
            [ "google.com", ".com/google.com_registrar_whois.txt", ".com/google.com_registrar_whois.json" ],

            [ "free.cr", ".cr/free.txt", null ],
            // [ "google.co.cr", ".cr/google.co.cr.txt", ".cr/google.co.cr.json" ],

            [ "free.cz", ".cz/free.txt", null ],
            // [ "google.cz", ".cz/google.cz.txt", ".cz/google.cz.json" ],

            [ "free.de", ".de/free.txt", null ],
            [ "google.de", ".de/google.de.txt", ".de/google.de.json" ],

            [ "free.dk", ".dk/free.txt", null ],
            // [ "google.dk", ".dk/google.dk.txt", ".dk/google.dk.json" ],

            [ "free.dm", ".dm/free.txt", null ],
            [ "google.dm", ".dm/google.dm.txt", ".dm/google.dm.json" ],

            [ "free.do", ".do/free.txt", null ],
            [ "google.com.do", ".do/google.com.do.txt", ".do/google.com.do.json" ],

            [ "free.dz", ".dz/free.txt", null ],
            [ "google.dz", ".dz/google.dz.txt", ".dz/google.dz.json" ],

            [ "free.ec", ".ec/free.txt", null ],
            // [ "google.com.ec", ".ec/google.com.ec.txt", ".ec/google.com.ec.json" ],

            [ "free.ee", ".ee/free.txt", null ],
            // [ "google.ee", ".ee/google.ee.txt", ".ee/google.ee.json" ],

            [ "free.fi", ".fi/free.txt", null ],
            [ "google.fi", ".fi/google.fi.txt", ".fi/google.fi.json" ],
            [ "xn--sisministeri-icb5x.fi", ".fi/xn--sisministeri-icb5x.fi.txt", ".fi/xn--sisministeri-icb5x.fi.json" ],
            [ "sisäministeriö.fi", ".fi/xn--sisministeri-icb5x.fi.txt", ".fi/xn--sisministeri-icb5x.fi.json" ],

            [ "free.fj", ".fj/free.txt", null ],
            // [ "google.com.fj", ".fj/google.com.fj.txt", ".fj/google.com.fj.json" ],

            [ "free.fm", ".fm/free.txt", null ],
            [ "google.fm", ".fm/google.fm.txt", ".fm/google.fm.json" ],

            [ "free.fr", ".fr/free.txt", null ],
            // [ "google.fr", ".fr/google.fr.txt", ".fr/google.fr.json" ],

            [ "free.ga", ".ga/free.txt", null ],
            // [ "google.ga", ".ga/google.ga.txt", ".ga/google.ga.json" ],

            [ "free.gd", ".gd/free.txt", null ],
            [ "google.gd", ".gd/google.gd.txt", ".gd/google.gd.json" ],

            [ "free.gf", ".gf/free.txt", null ],
            // [ "google.gf", ".gf/google.gf.txt", ".gf/google.gf.json" ],

            [ "free.gg", ".gg/free.txt", null ],
            // [ "google.gg", ".gg/google.gg.txt", ".gg/google.gg.json" ],

            [ "free.gi", ".gi/free.txt", null ],
            [ "google.com.gi", ".gi/google.com.gi.txt", ".gi/google.com.gi.json" ],

            [ "free.gl", ".gl/free.txt", null ],
            [ "google.gl", ".gl/google.gl.txt", ".gl/google.gl.json" ],

            [ "free.gov", ".gov/free.txt", null ],
            [ "usa.gov", ".gov/usa.gov.txt", ".gov/usa.gov.json" ],

            [ "free.gy", ".gy/free.txt", null ],
            [ "google.gy", ".gy/google.gy.txt", ".gy/google.gy.json" ],

            [ "free.hk", ".hk/free.txt", null ],
            // [ "google.com.hk", ".hk/google.com.hk.txt", ".hk/google.com.hk.json" ],

            [ "free.hr", ".hr/free.txt", null ],
            // [ "google.hr", ".hr/google.hr.txt", ".hr/google.hr.json" ],

            [ "free.ht", ".ht/free.txt", null ],
            [ "google.ht", ".ht/google.ht.txt", ".ht/google.ht.json" ],

            [ "free.hu", ".hu/free.txt", null ],
            [ "google.hu", ".hu/google.hu.txt", ".hu/google.hu.json" ],

            [ "free.id", ".id/free.txt", null ],
            [ "google.co.id", ".id/google.co.id.txt", ".id/google.co.id.json" ],

            [ "free.ie", ".ie/free.txt", null ],
            // [ "google.ie", ".ie/google.ie.txt", ".ie/google.ie.json" ],

            [ "free.il", ".il/free.txt", null ],
            // [ "google.co.il", ".il/google.co.il.txt", ".il/google.co.il.json" ],

            [ "free.im", ".im/free.txt", null ],
            // [ "google.im", ".im/google.im.txt", ".im/google.im.json" ],

            [ "free.in", ".in/free.txt", null ],
            [ "google.co.in", ".in/google.co.in.txt", ".in/google.co.in.json" ],

            [ "free.info", ".info/free.txt", null ],
            [ "info.info", ".info/info.info.txt", ".info/info.info.json" ],

            [ "free.io", ".io/free.txt", null ],
            [ "github.io", ".io/github.io.txt", ".io/github.io.json" ],
            [ "google.io", ".io/google.io.txt", ".io/google.io.json" ],

            [ "free.iq", ".iq/free.txt", null ],
            [ "google.iq", ".iq/google.iq.txt", ".iq/google.iq.json" ],

            [ "free.is", ".is/free.txt", null ],
            // [ "google.is", ".is/google.is.txt", ".is/google.is.json" ],

            [ "free.it", ".it/free.txt", null ],
            // [ "google.it", ".it/google.it.txt", ".it/google.it.json" ],

            [ "free.je", ".je/free.txt", null ],
            // [ "google.je", ".je/google.je.txt", ".je/google.je.json" ],

            [ "free.jp", ".jp/free.txt", null ],
            // [ "google.co.jp", ".jp/google.co.jp.txt", ".jp/google.co.jp.json" ],

            [ "free.kg", ".kg/free.txt", null ],
            // [ "google.kg", ".kg/google.kg.txt", ".kg/google.kg.json" ],

            [ "free.ki", ".ki/free.txt", null ],
            [ "google.ki", ".ki/google.ki.txt", ".ki/google.ki.json" ],

            [ "free.kr", ".kr/free.txt", null ],
            [ "google.co.kr", ".kr/google.co.kr.txt", ".kr/google.co.kr.json" ],

            [ "free.kz", ".kz/free.txt", null ],
            // [ "google.kz", ".kz/google.kz.txt", ".kz/google.kz.json" ],

            [ "free.la", ".la/free.txt", null ],
            [ "google.la", ".la/google.la.txt", ".la/google.la.json" ],

            [ "free.lc", ".lc/free.txt", null ],
            [ "google.com.lc", ".lc/google.com.lc.txt", ".lc/google.com.lc.json" ],

            [ "free.lt", ".lt/free.txt", null ],
            // [ "google.lt", ".lt/google.lt.txt", ".lt/google.lt.json" ],

            [ "free.lu", ".lu/free.txt", null ],
            // [ "google.lu", ".lu/google.lu.txt", ".lu/google.lu.json" ],

            [ "free.lv", ".lv/free.txt", null ],
            // [ "google.lv", ".lv/google.lv.txt", ".lv/google.lv.json" ],

            [ "free.ly", ".ly/free.txt", null ],
            // [ "google.com.ly", ".ly/google.com.ly.txt", ".ly/google.com.ly.json" ],

            [ "free.ma", ".ma/free.txt", null ],
            [ "google.co.ma", ".ma/google.co.ma.txt", ".ma/google.co.ma.json" ],

            [ "free.md", ".md/free.txt", null ],
            [ "google.md", ".md/google.md.txt", ".md/google.md.json" ],

            [ "free.me", ".me/free.txt", null ],
            [ "google.me", ".me/google.me.txt", ".me/google.me.json" ],

            [ "free.mg", ".mg/free.txt", null ],
            [ "google.mg", ".mg/google.mg.txt", ".mg/google.mg.json" ],

            [ "free.mk", ".mk/free.txt", null ],
            // [ "google.mk", ".mk/google.mk.txt", ".mk/google.mk.json" ],

            [ "free.ml", ".ml/free.txt", null ],
            // [ "google.ml", ".ml/google.ml.txt", ".ml/google.ml.json" ],

            [ "free.mn", ".mn/free.txt", null ],
            [ "google.mn", ".mn/google.mn.txt", ".mn/google.mn.json" ],

            [ "free.ms", ".ms/free.txt", null ],
            [ "google.ms", ".ms/google.ms.txt", ".ms/google.ms.json" ],

            [ "free.mu", ".mu/free.txt", null ],
            [ "google.mu", ".mu/google.mu.txt", ".mu/google.mu.json" ],

            [ "free.mx", ".mx/free.txt", null ],
            // [ "google.com.mx", ".mx/google.com.mx.txt", ".mx/google.com.mx.json" ],

            [ "free.mz", ".mz/free.txt", null ],
            [ "google.co.mz", ".mz/google.co.mz.txt", ".mz/google.co.mz.json" ],

            [ "free.na", ".na/free.txt", null ],
            [ "google.com.na", ".na/google.com.na.txt", ".na/google.com.na.json" ],

            [ "free.net", ".net/free.txt", null ],
            [ "speedtest.net", ".net/speedtest.net.txt", ".net/speedtest.net.json" ],
            [ "speedtest.net", ".net/speedtest.net_registrar_whois.txt", ".net/speedtest.net_registrar_whois.json" ],

            [ "free.nf", ".nf/free.txt", null ],
            [ "google.com.nf", ".nf/google.com.nf.txt", ".nf/google.com.nf.json" ],

            [ "free.ng", ".ng/free.txt", null ],
            [ "google.com.ng", ".ng/google.com.ng.txt", ".ng/google.com.ng.json" ],

            [ "free.nl", ".nl/free.txt", null ],
            // [ "google.nl", ".nl/google.nl.txt", ".nl/google.nl.json" ],

            [ "free.no", ".no/free.txt", null ],
            // [ "google.no", ".no/google.no.txt", ".no/google.no.json" ],

            [ "free.nu", ".nu/free.txt", null ],
            // [ "google.nu", ".nu/google.nu.txt", ".nu/google.nu.json" ],

            [ "free.nz", ".nz/free.txt", null ],
            // [ "google.co.nz", ".nz/google.co.nz.txt", ".nz/google.co.nz.json" ],

            [ "free.org", ".org/free.txt", null ],
            [ "linux.org", ".org/linux.org.txt", ".org/linux.org.json" ],

            [ "free.om", ".om/free.txt", null ],
            [ "google.com.om", ".om/google.com.om.txt", ".om/google.com.om.json" ],

            [ "free.pe", ".pe/free.txt", null ],
            [ "google.com.pe", ".pe/google.com.pe.txt", ".pe/google.com.pe.json" ],

            [ "free.pl", ".pl/free.txt", null ],
            // [ "google.pl", ".pl/google.pl.txt", ".pl/google.pl.json" ],

            [ "free.pr", ".pr/free.txt", null ],
            // [ "google.com.pr", ".pr/google.com.pr.txt", ".pr/google.com.pr.json" ],

            [ "free.ps", ".ps/free.txt", null ],
            [ "google.ps", ".ps/google.ps.txt", ".ps/google.ps.json" ],

            [ "free.qa", ".qa/free.txt", null ],
            [ "google.com.qa", ".qa/google.com.qa.txt", ".qa/google.com.qa.json" ],

            [ "free.ro", ".ro/free.txt", null ],
            [ "google.ro", ".ro/google.ro.txt", ".ro/google.ro.json" ],

            [ "free.rs", ".rs/free.txt", null ],
            [ "google.rs", ".rs/google.rs.txt", ".rs/google.rs.json" ],

            [ "free.ru", ".ru/free.txt", null ],
            [ "google.ru", ".ru/google.ru.txt", ".ru/google.ru.json" ],

            [ "free.rw", ".rw/free.txt", null ],
            [ "google.rw", ".rw/google.rw.txt", ".rw/google.rw.json" ],

            [ "free.sa", ".sa/free.txt", null ],
            // [ "google.com.sa", ".sa/google.com.sa.txt", ".sa/google.com.sa.json" ],

            [ "free.sb", ".sb/free.txt", null ],
            [ "google.com.sb", ".sb/google.com.sb.txt", ".sb/google.com.sb.json" ],

            [ "free.sc", ".sc/free.txt", null ],
            [ "google.sc", ".sc/google.sc.txt", ".sc/google.sc.json" ],

            [ "free.se", ".se/free.txt", null ],
            // [ "google.se", ".se/google.se.txt", ".se/google.se.json" ],

            [ "free.sg", ".sg/free.txt", null ],
            // [ "google.com.sg", ".sg/google.com.sg.txt", ".sg/google.com.sg.json" ],

            [ "free.sh", ".sh/free.txt", null ],
            [ "google.sh", ".sh/google.sh.txt", ".sh/google.sh.json" ],

            [ "free.si", ".si/free.txt", null ],
            // [ "google.si", ".si/google.si.txt", ".si/google.si.json" ],

            [ "free.sk", ".sk/free.txt", null ],
            // [ "google.sk", ".sk/google.sk.txt", ".sk/google.sk.json" ],

            [ "free.sl", ".sl/free.txt", null ],
            [ "google.com.sl", ".sl/google.com.sl.txt", ".sl/google.com.sl.json" ],

            [ "free.sm", ".sm/free.txt", null ],
            // [ "google.sm", ".sm/google.sm.txt", ".sm/google.sm.json" ],

            [ "free.sn", ".sn/free.txt", null ],
            // [ "google.sn", ".sn/google.sn.txt", ".sn/google.sn.json" ],

            [ "free.so", ".so/free.txt", null ],
            [ "google.so", ".so/google.so.txt", ".so/google.so.json" ],

            [ "free.st", ".st/free.txt", null ],
            [ "google.st", ".st/google.st.txt", ".st/google.st.json" ],

            [ "free.tg", ".tg/free.txt", null ],
            // [ "google.tg", ".tg/google.tg.txt", ".tg/google.tg.json" ],

            [ "free.th", ".th/free.txt", null ],
            [ "google.co.th", ".th/google.co.th.txt", ".th/google.co.th.json" ],

            [ "free.tk", ".tk/free.txt", null ],
            // [ "google.tk", ".tk/google.tk.txt", ".tk/google.tk.json" ],

            [ "free.tl", ".tl/free.txt", null ],
            [ "google.tl", ".tl/google.tl.txt", ".tl/google.tl.json" ],

            [ "free.tm", ".tm/free.txt", null ],
            [ "google.tm", ".tm/google.tm.txt", ".tm/google.tm.json" ],

            [ "free.tn", ".tn/free.txt", null ],
            // [ "google.com.tn", ".tn/google.com.tn.txt", ".tn/google.com.tn.json" ],

            [ "free.to", ".to/free.txt", null ],
            // [ "google.to", ".to/google.to.txt", ".to/google.to.json" ],

            [ "free.tr", ".tr/free.txt", null ],
            // [ "google.com.tr", ".tr/google.com.tr.txt", ".tr/google.com.tr.json" ],

            [ "free.tw", ".tw/free.txt", null ],
            // [ "google.com.tw", ".tw/google.com.tw.txt", ".tw/google.com.tw.json" ],

            [ "free.tz", ".tz/free.txt", null ],
            // [ "google.co.tz", ".tz/google.co.tz.txt", ".tz/google.co.tz.json" ],

            [ "free.ua", ".ua/free.txt", null ],
            [ "google.com.ua", ".ua/google.com.ua.txt", ".ua/google.com.ua.json" ],

            [ "free.uk", ".uk/free.txt", null ],
            // [ "google.co.uk", ".uk/google.co.uk.txt", ".uk/google.co.uk.json" ],

            [ "free.us", ".us/free.txt", null ],
            [ "google.us", ".us/google.us.txt", ".us/google.us.json" ],

            [ "free.uy", ".uy/free.txt", null ],
            // [ "google.uy", ".uy/google.uy.txt", ".uy/google.uy.json" ],

            [ "free.uz", ".uz/free.txt", null ],
            [ "google.uz", ".uz/google.uz.txt", ".uz/google.uz.json" ],

            [ "free.vc", ".vc/free.txt", null ],
            [ "google.com.vc", ".vc/google.com.vc.txt", ".vc/google.com.vc.json" ],

            [ "free.ve", ".ve/free.txt", null ],
            // [ "google.co.ve", ".ve/google.co.ve.txt", ".ve/google.co.ve.json" ],

            [ "free.vg", ".vg/free.txt", null ],
            [ "google.vg", ".vg/google.vg.txt", ".vg/google.vg.json" ],

            [ "free.vu", ".vu/free.txt", null ],
            // [ "google.vu", ".vu/google.vu.txt", ".vu/google.vu.json" ],

            [ "free.ws", ".ws/free.txt", null ],
            [ "google.ws", ".ws/google.ws.txt", ".ws/google.ws.json" ],

            [ "free.zm", ".zm/free.txt", null ],
            [ "google.co.zm", ".zm/google.co.zm.txt", ".zm/google.co.zm.json" ],

            // .рф
            [ "free.xn--p1ai", ".xn--p1ai/free.txt", null ],
            [ "xn--80a1acny.xn--p1ai", ".xn--p1ai/xn--80a1acny.xn--p1ai.txt", ".xn--p1ai/xn--80a1acny.xn--p1ai.json" ],
        ];

        foreach ($tests as $test) {
            list ($domain, $text, $json) = $test;
            self::assertTestData($domain, $text, $json);
        }
    }
}