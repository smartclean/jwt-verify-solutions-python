import os
from pprint import pformat
from dotenv import load_dotenv


def _load_env_vars_from_file():

    _test_dir_name = 'test'

    _absolute_dir_path_module = os.path.dirname(os.path.abspath(__name__))
    print(f'Absolute path to module directory is:\n{_absolute_dir_path_module}')

    _absolute_dir_path_module_test = f'{_absolute_dir_path_module}/test'

    _relative_path_to_env_file = '.env'
    print(f'_relative_path_to_env_file is:\n{_relative_path_to_env_file}')

    path_to_environment_file = f'{_absolute_dir_path_module_test}/{_relative_path_to_env_file}'
    print(f'Loading environment variables from file:\n{path_to_environment_file}')

    if os.path.isfile(path_to_environment_file) is False:
        raise FileNotFoundError(f'Tip: Please create the file or update the definition: '
                                f'"PROJECT_RELATIVE_PATH_TO_ENVIRONMENT_FILE" (File not found at path:'
                                f'\n{path_to_environment_file})')

    load_response = load_dotenv(path_to_environment_file)

    if load_response is True:
        print(f'Successfully loaded environment variables from file:\n{path_to_environment_file}')
    else:
        raise Exception(f'Failed to load environment variables from file:\n{path_to_environment_file}')


def test_jwt_issuer_get_well_known_jwks() -> None or AssertionError:
    """

    Test jwt_issuer request: Get well known JWKS

    :return:

    sample_response = {
        'code': 'SUCCESS',
        'data': {
            'keys': [
                {'alg': 'RS256',
                 'e': 'AQAB',
                 'kid': 'F1cvSWpi3W1UZRxKebIu9Jzp0XinvaSNhPP3qN9/Hj0=',
                 'kty': 'RSA',
                 'n': 'zjMAr5h87FLCxOK9klXic-5l0yJ94xDEOfM7X83tiy2xHf60LKJUyQqbXv1SOoGGWxTBr1QRAcLhE14_IMkS016ZKkyBp11r4baakTPRwep9MMjN8d6noSFcmpgyVrzBjCGbZlfCFeexE9Xwch9GJZvOaWGYAaH_nD9wNm_cdbX8spWSa90mpgqTNAK04hu4HiWzw1d_r5P3i3RQWpwFZqCMluQhieKhUO9PScgPg2ZiTLnUoq-pn_Kw7t-UbKRiJ6m7eE6ISewxP9lvx4Zqo_fI78CDh5xdMnqk5qKSPkiS4C-mVhUUZqCpKmpUaD7SEqoPX4QPdBnIvC8fgkOkJw',
                 'use': 'sig'},
                {'alg': 'RS256',
                 'e': 'AQAB',
                 'kid': 'Qe9PQu3al/g2O9m8tV2DGz7dWsV61tXpUEOfbrdNj8k=',
                 'kty': 'RSA',
                 'n': 'qu23nA-EEFAJPuDpz5vp3xsNTFqk9vQ-k5oPJtCdruIn0kmuHeHFtpz_9TuYCiuyfIo3XDx_n_K-zwxzZH-wUXg17autaBbFjKg7MDDDLjKMM5tg4qH1XWrQQGcwpZwk2dR5SDSmB5Ufm5EmRve6k_0hPO-3Ysh89CPCagMdfJXjLrQXW2licSYh7N1oboo0mnmbRZrR-Sn77vruAfwg7Ew8l3QG7t4AoaFC90s-1Ri3wsC3zwN4DHqR1aijfI_p4Tfh6FdWtS_BvY5ksFp-0yXFYQ7ZD6lJ2OoAS1Mb-zQ5BEhN-EGirzGIyV-1hRQetqlszsxXpgYaX_ww89-X4Q',
                 'use': 'sig'}
            ]
        },
        'message': 'Successfully obtained desired data from Get request to well-known JWKS for an AWS Cognito User Pool'
    }
    """

    _request_name = 'Get well known JWKS'

    _api_name = 'jwt_issuer'

    api_request_name = f'{_api_name}/{_request_name}'

    from api.jwt_issuer import fetch_well_known_jwks_from_token_issuer

    response = fetch_well_known_jwks_from_token_issuer(_request_name)
    print(f'Test complete, response is: {pformat(response)}')

    if 'code' in response:
        assert response['code'] == 'SUCCESS', f'"code" in response is: {response["code"]} (Expected "SUCCESS")'

    assert 'requestUrl' in response, f'"requestUrl" missing in response of {api_request_name}'

    assert 'data' in response, f'"data" missing in response of {api_request_name}'

    jwks_data = response['data']

    assert "keys" in jwks_data, f'"keys" missing in response "data" of {api_request_name}'

    assert type(jwks_data["keys"]) is list, f'"keys" in response "data" of {api_request_name} must be list'

    print(f'Test: {api_request_name} successful!')


if __name__ == '__main__':
    _load_env_vars_from_file()
    test_jwt_issuer_get_well_known_jwks()
