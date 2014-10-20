<?php

namespace Tc\JOSE\Util;

use Tc\JOSE\Exception\JSONException;

/**
 * Json Encode and Decode Methods
 *
 * @package Tc\JOSE\Util
 * @author Carl Craig <carlcraig@3c-studios.com>
 */
class JSON
{
    /**
     * Encodes an object/array into a JSON string
     *
     * @param object|array $input The input object or array to be encoded into a JSON string
     * @return string The encoded input in a JSON string
     * @throws \Tc\JOSE\Exception\JSONException If the input object/array could not be encoded into valid JSON
     */
    public static function encode($input)
    {
        $encoded = json_encode($input);
        if (function_exists('json_last_error') && $error = json_last_error()) {
            throw new JSONException(self::transformJsonError($error));
        } elseif ($encoded === 'null' && $input !== null) {
            throw new JSONException('Null encoded result');
        }

        return $encoded;
    }

    /**
     * Decodes a JSON string into an associative array
     *
     * @param string $jsonString The input JSON string to be decoded
     * @return array An associative array of the decoded JSON
     * @throws \Tc\JOSE\Exception\JSONException If the jsonString was invalid JSON
     */
    public static function decode($jsonString)
    {
        $object = json_decode($jsonString, true);
        if (function_exists('json_last_error') && $error = json_last_error()) {
            throw new JSONException(self::transformJsonError($error));
        } elseif ($object === null) {
            throw new JSONException('Null decoded result.');
        }

        return $object;
    }

    /**
     * Transforms a JSON error identifier into a string error message
     *
     * @param integer $error The JSON error integer identifier.
     * @return string The error message for given JSON error.
     */
    private static function transformJsonError($error)
    {
        switch ($error) {
            case JSON_ERROR_DEPTH:
                return 'Maximum stack depth exceeded.';
            case JSON_ERROR_STATE_MISMATCH:
                return 'Underflow or the modes mismatch.';
            case JSON_ERROR_CTRL_CHAR:
                return 'Unexpected control character found.';
            case JSON_ERROR_SYNTAX:
                return 'Syntax error, malformed JSON.';
            case JSON_ERROR_UTF8:
                return 'Malformed UTF-8 characters, possibly incorrectly encoded.';
            default:
                return 'Unknown error.';
        }
    }
}
