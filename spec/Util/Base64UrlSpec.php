<?php

namespace spec\Tc\JOSE\Util;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

/**
 * Base64UrlSpec
 *
 * @package spec\Tc\JOSE\Util
 * @author Carl Craig <carlcraig@3c-studios.com>
 * @mixin \Tc\JOSE\Util\Base64Url
 */
class Base64UrlSpec extends ObjectBehavior
{
    function it_should_encode_data_to_base_64_url_safe()
    {
        $this::encode('1234567')->shouldReturn('MTIzNDU2Nw');
        $this::encode('12345678')->shouldReturn('MTIzNDU2Nzg');
        $this::encode('123456789')->shouldReturn('MTIzNDU2Nzg5');
        $this::encode('Hello"\/World"@~#%$£\'\'')->shouldReturn('SGVsbG8iXC9Xb3JsZCJAfiMlJMKjJyc');
    }

    function it_should_decode_data_that_it_encodes()
    {
        $this::decode($this::encode('1234567'))->shouldReturn('1234567');
        $this::decode($this::encode('12345678'))->shouldReturn('12345678');
        $this::decode($this::encode('123456789'))->shouldReturn('123456789');
        $this::decode($this::encode('Hello"\/World"@~#%$£\'\''))->shouldReturn('Hello"\/World"@~#%$£\'\'');
    }
}
