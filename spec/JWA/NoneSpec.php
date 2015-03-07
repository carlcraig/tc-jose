<?php

namespace spec\Tc\JOSE\JWA;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

/**
 * NoneSpec
 *
 * @package spec\Tc\JOSE\JWA
 * @author Carl Craig <carlcraig@3c-studios.com>
 * @mixin \Tc\JOSE\JWA\None
 */
class NoneSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Tc\JOSE\JWA\None');
    }

    function it_should_sign_data()
    {
        $this->sign('123', 'key')->shouldReturn('');
    }

    function it_should_verify_a_valid_signature()
    {
        $this->verify('key', $this->sign('123', 'key'), '123')->shouldReturn(true);
    }

    function it_should_not_verify_a_invalid_signature()
    {
        $this->verify('key', 'invalidSignature', '123')->shouldReturn(false);
    }
}
