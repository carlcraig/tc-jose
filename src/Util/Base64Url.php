<?php

namespace Tc\JOSE\Util;

/**
 * Base64 URL Encode and Decode Methods
 *
 * @package Tc\JOSE\Util
 * @author Carl Craig <carlcraig@3c-studios.com>
 */
class Base64Url
{
    /**
     * Encodes data into base64 Url-Safe
     *
     * @param string $data The input data to be encoded
     * @return string The base64 Url-Safe encoded data
     */
    public static function encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decodes data from base64 Url-Safe into a string.
     *
     * @param string $data The input base64url encoded string to be decoded
     * @return string The decoded base64url string
     */
    public static function decode($data)
    {
        return base64_decode(
            str_pad(strtr($data, '-_', '+/'), strlen($data) + (strlen($data) % 4), '=', STR_PAD_RIGHT)
        );
    }
}
