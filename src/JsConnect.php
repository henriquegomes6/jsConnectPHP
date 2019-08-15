<?php
namespace HenriqueGomes6;

class JsConnect
{
    const JS_CONNECT_VERSION = '2';
    const JS_TIMEOUT         = 1440;

    private $header;
    private $clientId;
    private $secret;

    public function __construct(
        string $clientId,
        string $secret
    ) {
        $this->clientId = $clientId;
        $this->secret   = $secret;
        $this->header   = 'application/json; charset=utf-8';
    }

    public function writeJsConnect($user, $request, $secure = true)
    {
        $user = array_change_key_case($user);

        // Error checking.
        if ($secure) {
            // Check the client.
            if (!isset($request['v'])) {
                $error = ['error' => 'invalid_request', 'message' => 'Missing the v parameter.'];
            } elseif ($request['v'] !== self::JS_CONNECT_VERSION) {
                $error = array('error' => 'invalid_request', 'message' => "Unsupported version {$request['v']}.");
            } elseif (!isset($request['client_id'])) {
                $error = ['error' => 'invalid_request', 'message' => 'Missing the client_id parameter.'];
            } elseif ($request['client_id'] != $this->clientId) {
                $error = ['error' => 'invalid_client', 'message' => "Unknown client {$request['client_id']}."];
            } elseif (!isset($request['timestamp']) && !isset($request['sig'])) {
                if (is_array($user) && count($user) > 0) {
                    // This isn't really an error, but we are just going to return public information when no signature is sent.
                    $error = ['name' => (string) @$user['name'], 'photourl' => @$user['photourl'], 'signedin' => true];
                } else {
                    $error = ['name' => '', 'photourl' => ''];
                }
            } elseif (!isset($request['timestamp']) || !ctype_digit($request['timestamp'])) {
                $error = ['error' => 'invalid_request', 'message' => 'The timestamp parameter is missing or invalid.'];
            } elseif (!isset($request['sig'])) {
                $error = ['error' => 'invalid_request', 'message' => 'Missing the sig parameter.'];
            } // Make sure the timestamp hasn't timedout
            elseif (abs($request['timestamp'] - $this->jsTimestamp()) > self::JS_TIMEOUT) {
                $error = ['error' => 'invalid_request', 'message' => 'The timestamp is invalid.'];
            } elseif (!isset($request['nonce'])) {
                $error = ['error' => 'invalid_request', 'message' => 'Missing the nonce parameter.'];
            } elseif (!isset($request['ip'])) {
                $error = ['error' => 'invalid_request', 'message' => 'Missing the ip parameter.'];
            } else {
                $signature = $this->jsHash($request['ip'] . $request['nonce'] . $request['timestamp'] . $this->secret, $secure);
                if ($signature != $request['sig']) {
                    $error = ['error' => 'access_denied', 'message' => 'Signature invalid.'];
                }
            }
        }

        if (isset($error)) {
            $result = $error;
        } elseif (is_array($user) && count($user) > 0) {
            if ($secure === null) {
                $result = $user;
            } else {
                $user['ip']    = $request['ip'];
                $user['nonce'] = $request['nonce'];
                $result        = $this->signJsConnect($user, $secure, true);
                $result['v']   = self::JS_CONNECT_VERSION;
            }
        } else {
            $result = ['name' => '', 'photourl' => ''];
        }

        $json = json_encode($result);

        if (isset($request['callback'])) {
            $this->header = 'application/javascript; charset=utf-8';
            return "{$request['callback']}($json)";
        }
        return $json;
    }

    public function getHeader()
    {
        return $this->header;
    }

    /**
     *
     *
     * @param $data
     * @param $hashType
     * @param bool $returnData
     * @return array|string
     */
    public function signJsConnect($data, $hashType, $returnData = false)
    {
        $normalizedData = array_change_key_case($data);
        ksort($normalizedData);

        foreach ($normalizedData as $key => $value) {
            if ($value === null) {
                $normalizedData[$key] = '';
            }
        }

        // RFC1738 state that spaces are encoded as '+'.
        $stringifiedData = http_build_query($normalizedData, null, '&', PHP_QUERY_RFC1738);
        $signature       = $this->jsHash($stringifiedData . $this->secret, $hashType);
        if ($returnData) {
            $normalizedData['client_id'] = $this->clientId;
            $normalizedData['sig']       = $signature;
            return $normalizedData;
        } else {
            return $signature;
        }
    }

    /**
     * Return the hash of a string.
     *
     * @param string $string The string to hash.
     * @param string|bool $secure The hash algorithm to use. true means md5.
     * @return string
     */
    public function jsHash($string, $secure = true)
    {
        if ($secure === true) {
            $secure = 'md5';
        }

        switch ($secure) {
            case 'sha1':
                return sha1($string);
                break;
            case 'md5':
            case false:
                return md5($string);
            default:
                return hash($secure, $string);
        }
    }

    /**
     *
     *
     * @return int
     */
    public function jsTimestamp()
    {
        return time();
    }

    /**
     * Generate an SSO string suitable for passing in the url for embedded SSO.
     *
     * @param array $user The user to sso.
     * @return string
     */
    public function jsSSOString($user)
    {
        if (!isset($user['client_id'])) {
            $user['client_id'] = $this->clientId;
        }

        $string    = base64_encode(json_encode($user));
        $timestamp = time();
        $hash      = hash_hmac('sha1', "$string $timestamp", $this->secret);

        $result = "$string $hash $timestamp hmacsha1";
        return $result;
    }
}
