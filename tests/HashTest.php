<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2017 Vanilla Forums Inc.
 * @license GNU GPLv2 http://www.opensource.org/licenses/gpl-2.0.php
 */

namespace HenriqueGomes6;

use PHPUnit\Framework\TestCase;

/**
 * Unit tests hashing
 */
class HashTest extends TestCase
{
    /** @var JsConnect */
    private $jsConnect;
    public function setUp(): void
    {
        parent::setUp();

        $this->jsConnect = new JsConnect;
    }

    /**
     *  Test {@link jsHash} with no $secure parameter.
     */
    public function testHashDefault()
    {
        $this->assertEquals(md5('hashMe'), $this->jsConnect->jsHash('hashMe'));
    }

    /**
     *  Test {@link jsHash} with true as the $secure parameter.
     */
    public function testHashSecureTrue()
    {
        $this->assertEquals(md5('hashMe'), $this->jsConnect->jsHash('hashMe', true));
    }

    /**
     *  Test {@link jsHash} with 'md5' as the $secure parameter.
     */
    public function testHashSecureMD5()
    {
        $this->assertEquals(md5('hashMe'), $this->jsConnect->jsHash('hashMe', 'md5'));
    }

    /**
     *  Test {@link jsHash} with 'sha256' as the $secure parameter.
     */
    public function testHashSecureSHA256()
    {
        $this->assertEquals(hash('sha256', 'hashMe'), $this->jsConnect->jsHash('hashMe', 'sha256'));
    }
}
