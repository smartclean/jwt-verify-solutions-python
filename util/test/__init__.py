from util.jwk_to_pem import convert_to_rsa_public_key
from util.test import jwk_pem_data

# TODO: Add tests for logging and type_check modules


def run_test():

    valid_jwk_object_1 = jwk_pem_data.VALID_JWK_OBJECT_1
    public_key_for_valid_jwk_object_1 = jwk_pem_data.PUBLIC_KEY_FOR_VALID_JWK_OBJECT_1

    test_convert_jwk_to_pem(
        jwk_object=valid_jwk_object_1,
        valid=True,
        rsa_public_key=public_key_for_valid_jwk_object_1
    )

    invalid_jwk_object_1 = jwk_pem_data.INVALID_JWK_OBJECT_1

    test_convert_jwk_to_pem(
        jwk_object=invalid_jwk_object_1,
        valid=False
    )


def test_convert_jwk_to_pem(jwk_object: dict, valid: bool, rsa_public_key: str = None):

    get_public_key_resp = convert_to_rsa_public_key(jwk_object)

    public_key = get_public_key_resp['value']
    get_public_key_message = get_public_key_resp['message']

    if valid is True:
        if public_key is None:
            raise Exception(f'Test convert valid JWK to PEM failed. Details: {get_public_key_message}')

        if public_key != rsa_public_key:
            raise Exception('Converted public did not match expected public key given for this JWK object')

        print('Verified conversion of valid JWK object to RSA public key is correct')
    else:

        if public_key is not None:
            raise Exception('Test convert invalid JWK to PEM yielded a public key (unexpected)')
        print('Verified conversion of invalid JWK object to RSA Public key did not yield a key')


if __name__ == '__main__':
    run_test()


