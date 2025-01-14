<?php
/**
 * @author Alexandre (DaazKu) Chouinard <alexandre.c@vanillaforums.com>
 * @copyright 2009-2017 Vanilla Forums Inc.
 * @license GNU GPLv2 http://www.opensource.org/licenses/gpl-2.0.php
 */

namespace HenriqueGomes6;

use PHPUnit\Framework\TestCase;

/**
 * Unit tests signJsConnect
 */
class WriteJsConnectTest extends TestCase
{
    /** @var JsConnect */
    private $jsConnect;
    public function setUp(): void
    {
        parent::setUp();
        $this->jsConnect = new JsConnect;
    }
    /**
     * @param $user
     * @param $request
     * @param $clientID
     * @param $secret
     * @param $secure
     * @param $expectedResult
     *
     * @dataProvider provideWriteJsConnectTests
     */
    public function testWriteJsConnect($user, $request, $clientID, $secret, $secure, $expectedResult)
    {
        $result = $this->jsConnect->writeJsConnect($user, $request, $clientID, $secret, $secure);

        $result = json_decode($result, true);
        ksort($result);

        $this->assertEquals($result, $expectedResult);
    }

    /**
     * Provide signature to sign
     *
     * @return array Returns a test array.
     */
    public function provideWriteJsConnectTests()
    {
        $this->jsConnect = new JsConnect;

        $clientID  = 'clientID';
        $timestamp = time();
        $secret    = 'secret';
        $ip        = '127.0.0.1';
        $secure    = 'sha256';
        $nonce     = 'nonceToken';
        $sig       = $this->jsConnect->jsHash($ip . $nonce . $timestamp . $secret, $secure);
        $sig       = '';
        $version   = '2';

        $userData = array(
            'name'      => 'John PHP',
            'email'     => 'john.php@example.com',
            'unique_id' => '123',
        );
        $jsConnect          = $this->jsConnect;
        $fnGenerateTestData = function () use (&$userData, &$clientID, &$timestamp, &$secret, &$ip, &$secure, &$nonce, &$sig, &$version, $jsConnect) {
            $request = array(
                'client_id' => $clientID,
                'ip'        => $ip,
                'nonce'     => $nonce,
                'sig'       => $sig,
                'timestamp' => $timestamp,
                'v'         => $version,
            );

            $expectedResult = array(
                'sig' => $jsConnect->signJsConnect(
                    $userData + ['ip' => $ip, 'nonce' => $nonce],
                    $clientID,
                    $secret,
                    $secure
                ),
            ) + $request + $userData;
            unset($expectedResult['timestamp']);
            ksort($expectedResult);

            return [
                'userData'       => $userData,
                'request'        => $request,
                'clientID'       => $clientID,
                'secret'         => $secret,
                'secure'         => $secure,
                'expectedResult' => $expectedResult,
            ];
        };

        $fnGenerateAlteratedData = function (&$var, $value, $expectedResult) use ($fnGenerateTestData) {
            $tmpVar                 = $var;
            $var                    = $value;
            $data                   = $fnGenerateTestData();
            $var                    = $tmpVar;
            $data['expectedResult'] = $expectedResult;
            return $data;
        };

        $data = [];

        // Wrong version
        $data['wrongVersion'] = $fnGenerateAlteratedData(
            $version, 1, array('error' => 'invalid_request', 'message' => "Unsupported version 1.")
        );

        // Missings
        $missings = array('v', 'client_id', 'sig', 'nonce', 'ip');
        foreach ($missings as $missing) {
            $tmp = $fnGenerateTestData();
            unset($tmp['request'][$missing]);
            $tmp['expectedResult']     = array('error' => 'invalid_request', 'message' => "Missing the $missing parameter.");
            $data["missing[$missing]"] = $tmp;
        }

        // Missing timestamp
        $tmp = $fnGenerateTestData();
        unset($tmp['request']['timestamp']);
        $tmp['expectedResult']      = array('error' => 'invalid_request', 'message' => 'The timestamp parameter is missing or invalid.');
        $data['missing[timestamp]'] = $tmp;

        // Non numeric timestamp
        $data['invalidTimestamp'] = $fnGenerateAlteratedData(
            $timestamp, 'notatimestamp', array('error' => 'invalid_request', 'message' => 'The timestamp parameter is missing or invalid.')
        );

        // Timed Out timestamp
        $data['timedOutTimestamp'] = $fnGenerateAlteratedData(
            $timestamp, ($timestamp - (JsConnect::JS_TIMEOUT + 1)), array('error' => 'invalid_request', 'message' => 'The timestamp is invalid.')
        );

        // Bad client_id
        $tmp                         = $fnGenerateTestData();
        $tmp['request']['client_id'] = 'wrong' . $clientID;
        $tmp['expectedResult']       = array('error' => 'invalid_client', 'message' => "Unknown client {$tmp['request']['client_id']}.");
        $data['wrongClientID']       = $tmp;

        // No sig, no timestamp sent with user logged
        $tmp = $fnGenerateTestData();
        unset($tmp['request']['sig'], $tmp['request']['timestamp']);
        $tmp['expectedResult']    = array('name' => 'John PHP', 'photourl' => null, 'signedin' => true);
        $data['noSigNoTimestamp'] = $tmp;

        // No sig, no timestamp sent with user not logged
        $tmp             = $fnGenerateTestData();
        $tmp['userData'] = [];
        unset($tmp['request']['sig'], $tmp['request']['timestamp']);
        $tmp['expectedResult']    = array('name' => '', 'photourl' => '');
        $data['noSigNoTimestamp'] = $tmp;

        // Bad signature
        $data['badSignature'] = $fnGenerateAlteratedData(
            $ip, '255.255.255.255', array('error' => 'access_denied', 'message' => 'Signature invalid.')
        );

        // Secure disabled
        $data['timedOutTimestamp'] = $fnGenerateAlteratedData($secure, null, $userData);

        return $data;
    }
}
