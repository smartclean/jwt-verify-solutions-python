import os
from pprint import pformat

import requests

_ENV_VAR_NAME_AWS_COGNITO_IDP_BASE_URL = 'AWS_COGNITO_IDP_BASE_URL'
_ENV_VAR_NAME_AWS_COGNITO_DESIRED_USER_POOL = 'AWS_COGNITO_DESIRED_USER_POOL'


def _ensure_required_environment_variables_set():

    if _ENV_VAR_NAME_AWS_COGNITO_DESIRED_USER_POOL not in os.environ:
        raise Exception(f'Required variable: {_ENV_VAR_NAME_AWS_COGNITO_DESIRED_USER_POOL} not found in this environment.')

    if _ENV_VAR_NAME_AWS_COGNITO_IDP_BASE_URL not in os.environ:
        raise Exception(f'Required variable: {_ENV_VAR_NAME_AWS_COGNITO_IDP_BASE_URL} not found in this environment.')


_ensure_required_environment_variables_set()


def get_jwks_json_for_user_pool(request_name: str, user_pool_id: str = None) -> dict:

    data_return = {
        'data': None,
        'code': None,
        'message': 'default'
    }

    print(f'Preparing: {request_name}')

    if user_pool_id is None:
        user_pool_id = os.environ[_ENV_VAR_NAME_AWS_COGNITO_DESIRED_USER_POOL]

    base_url = os.environ[_ENV_VAR_NAME_AWS_COGNITO_IDP_BASE_URL]

    request_url = f'{base_url}/{user_pool_id}/.well-known/jwks.json'
    data_return['requestUrl'] = request_url

    request_headers = {
        'Content-Type': 'application/json'
    }

    response = requests.get(
        url=request_url,
        headers=request_headers
    )

    response_status_code = response.status_code
    status_code_message = f'response status code is: {response_status_code}'

    if response_status_code != 200:
        response_reason = response.reason
        data_return['message'] = f'{request_name} failed ({status_code_message})'
        data_return['code'] = response_reason
        return data_return

    print(f'{request_name} complete!')
    print(status_code_message)

    try:
        response_json = response.json()
    except Exception as err:
        _err_type = type(err).__name__
        _err_text = str(err)
        data_return['code'] = _err_type
        data_return['message'] = f'Response data does not have a valid JSON ({_err_text})'
        print(data_return['message'])
        return data_return

    data_return['code'] = 'SUCCESS'
    data_return['data'] = response_json
    data_return['message'] = f'Successfully obtained desired data from {request_name}'
    print(data_return['message'])
    return data_return
