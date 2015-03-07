<?php

namespace spec\Tc\JOSE\Util;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Tc\JOSE\Exception\JSONException;

/**
 * JSONSpec
 *
 * @package spec\Tc\JOSE\Util
 * @author Carl Craig <carlcraig@3c-studios.com>
 * @mixin \Tc\JOSE\Util\JSON
 */
class JSONSpec extends ObjectBehavior
{
    function it_should_encode_data_into_json()
    {
        $this::encode(null)->shouldReturn('null');
        $this::encode(array('message' => 'hello world'))->shouldReturn('{"message":"hello world"}');
    }

    function it_should_decode_json_into_array()
    {
        $this::decode(self::encode(array('message' => 'hello world')))->shouldReturn(array('message' => 'hello world'));
    }

    function it_should_throw_exception_when_decoding_invalid_json()
    {
        $this->shouldThrow(new JSONException('Syntax error, malformed JSON.'))->duringDecode('}{');
    }
}
