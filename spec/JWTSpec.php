<?php

namespace spec\Tc\JOSE;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Tc\JOSE\Util\Base64Url;
use Tc\JOSE\Util\JSON;

/**
 * JWTSpec
 *
 * @package spec\Tc\JOSE
 * @author Carl Craig <carlcraig@3c-studios.com>
 * @mixin \Tc\JOSE\JWT
 */
class JWTSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Tc\JOSE\JWT');
    }

    function it_should_set_and_get_header()
    {
        $this->setHeader(array('alg' => 'none', 'typ' => 'JOSE'));
        $this->getHeader()->shouldReturn(array('alg' => 'none', 'typ' => 'JOSE'));
    }

    function it_should_set_and_get_payload()
    {
        $this->setPayload(array('sub' => 'TEST'));
        $this->getPayload()->shouldReturn(array('sub' => 'TEST'));
    }

    function it_should_create_jws_signing_input()
    {
        $this->setHeader(array('alg' => 'none', 'typ' => 'JOSE'));
        $this->setPayload(array('sub' => 'TEST'));
        $expectedJWSSigningInput = sprintf(
            '%s.%s',
            Base64Url::encode(JSON::encode(array('alg' => 'none', 'typ' => 'JOSE'))),
            Base64Url::encode(JSON::encode(array('sub' => 'TEST')))
        );
        $this->generateJWSSigningInput()->shouldReturn($expectedJWSSigningInput);
    }

    function it_should_decode_a_jws()
    {
        $encodedJWS = sprintf(
            '%s.%s.',
            Base64Url::encode(JSON::encode(array('alg' => 'none', 'typ' => 'JOSE'))),
            Base64Url::encode(JSON::encode(array('sub' => 'TEST')))
        );
        $this->decode($encodedJWS)->shouldReturnAnInstanceOf('Tc\JOSE\JWS');
    }

    function it_should_not_decode_an_invalid_jws_token()
    {
        $invalidJOSE = '1.2.3';
        $this->shouldThrow(new \InvalidArgumentException('The JWS is Invalid or Malformed'))->duringDecode(
            $invalidJOSE
        );
    }

    function it_should_not_decode_an_invalid_jose_token()
    {
        $invalidJOSE = '1';
        $this->shouldThrow(new \InvalidArgumentException('The JOSE token is Invalid or Malformed'))->duringDecode(
            $invalidJOSE
        );
    }

    function it_should_not_decode_a_jwe_token_as_it_is_not_supported()
    {
        $invalidJOSE = '1.2.3.4.5';
        $this->shouldThrow(
            new \InvalidArgumentException('The JOSE token is a JWE which is currently not supported')
        )->duringDecode($invalidJOSE);
    }

    function it_should_allow_expires_claim_to_be_set_with_seconds()
    {
        $this->setExpires(50);
        $this->getPayload()->shouldHaveKey('exp');
    }

    function it_should_allow_expires_claim_to_be_set_with_datetime()
    {
        $this->setExpires(new \DateTime('now'));
        $this->getPayload()->shouldHaveKey('exp');
    }

    function it_should_allow_issued_at_claim_to_be_set()
    {
        $this->setIssuedAt();
        $this->getPayload()->shouldHaveKey('iat');
    }

    function it_should_allow_issued_at_claim_to_be_set_with_datetime()
    {
        $this->setIssuedAt(new \DateTime('tomorrow'));
        $this->getPayload()->shouldHaveKey('iat');
    }

    function it_should_check_if_the_jwt_is_expired_given_an_expired_jwt()
    {
        $this->setExpires(new \DateTime('yesterday'));
        $this->isExpired()->shouldReturn(true);
    }

    function it_should_check_if_the_jwt_is_expired_given_a_valid_jwt()
    {
        $this->setExpires(new \DateTime('tomorrow'));
        $this->isExpired()->shouldReturn(false);

    }

    function it_should_not_be_expired_when_no_exp_claim_was_set()
    {
        $this->isExpired()->shouldReturn(false);
    }

    function it_should_be_able_to_validate_the_jwt()
    {
        $this->validate()->shouldReturn(true);

    }
}
