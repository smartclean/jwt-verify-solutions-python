"""
Code in this module is adapted from:
Project: okta-jwks-to-pem (creator: jpf)
https://github.com/jpf/okta-jwks-to-pem
"""

import six
import base64
import struct

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from util import data_ops

# TODO: Test against all possible exceptions and handle them...


def convert_to_rsa_public_key(jwk_object: dict) -> dict:
    """
    Converts given JWK object to an RSA Public Key

    :param jwk_object:
    :return:
    """

    data_return = {
        'value': None,
        'message': 'default'
    }

    print('Converting JWK object to RSA Public Key')

    # region Extract and validate "e" (exponent) from JWK object
    get_exponent_response = data_ops.extract_attr_from_dictionary(
        data=jwk_object,
        data_name='jwk object',
        attr_name='e',
        exp_type=str
    )

    _rsa_exponent = get_exponent_response['value']
    _extract_rsa_exponent_status = get_exponent_response['text']

    if _rsa_exponent is None:
        data_return['message'] = _extract_rsa_exponent_status
        return data_return
    # endregion

    # region Convert RSA exponent to numeric value
    convert_rsa_exponent_to_int_resp = _base64_to_long_integer(_rsa_exponent, '"e"(RSA Exponent)')
    rsa_exponent_integer = convert_rsa_exponent_to_int_resp['value']
    convert_rsa_exponent_to_int_message = convert_rsa_exponent_to_int_resp['message']

    if rsa_exponent_integer is None:
        data_return['message'] = convert_rsa_exponent_to_int_message
        return data_return
    # endregion

    # region Extract and validate "n" (modulus) from JWK object
    get_modulus_response = data_ops.extract_attr_from_dictionary(
        data=jwk_object,
        data_name='jwk object',
        attr_name='n',
        exp_type=str
    )

    _rsa_modulus = get_modulus_response['value']
    _extract_rsa_modulus_status = get_modulus_response['text']

    if _rsa_modulus is None:
        data_return['message'] = _extract_rsa_modulus_status
        return data_return
    # endregion

    # region Convert RSA modulus to numeric value

    convert_rsa_modulus_to_int_resp = _base64_to_long_integer(_rsa_modulus, '"n"(RSA Modulus)')
    rsa_modulus_integer = convert_rsa_modulus_to_int_resp['value']
    convert_rsa_modulus_to_int_message = convert_rsa_modulus_to_int_resp['message']

    if rsa_modulus_integer is None:
        data_return['message'] = convert_rsa_modulus_to_int_message
        return data_return

    # endregion

    numbers = RSAPublicNumbers(rsa_exponent_integer, rsa_modulus_integer)

    public_key = numbers.public_key(backend=default_backend())

    _pem_bytes_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print('JWK conversion to PEM complete')

    decoded_pem = _pem_bytes_str.decode('utf-8')

    data_return['value'] = decoded_pem
    data_return['message'] = 'JWK to PEM Conversion complete'

    return data_return


def _base64_to_long_integer(data, data_name: str) -> dict:

    data_return = {
        'value': None,
        'message': 'default'
    }

    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    try:
        _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    except Exception as err:
        _err_type = type(err).__name__
        _err_text = str(err)

        err_info = f'{_err_type} in base64_to_long() process for {data_name} ({_err_text})'

        data_return['message'] = err_info
        return data_return

    desired_value = _intarr2long(struct.unpack('%sB' % len(_d), _d))
    data_return['value'] = desired_value
    data_return['message'] = 'base64_to_long_integer() process complete!'

    return data_return


def _intarr2long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)
