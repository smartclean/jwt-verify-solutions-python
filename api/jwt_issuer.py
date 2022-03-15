import os

import requests

import definitions
from util.logger import get_logger_for_module

_LOG_LEVEL = os.getenv('LOG_LEVEL', 'debug')
LOG = get_logger_for_module(__name__, _LOG_LEVEL)


ENV_VAR_NAME_TOKEN_ISSUER_URL = definitions.ENV_VAR_NAME_TOKEN_ISSUER_URL


def ensure_required_environment_variables_found():

    if ENV_VAR_NAME_TOKEN_ISSUER_URL not in os.environ:
        raise Exception(f'Required variable: {ENV_VAR_NAME_TOKEN_ISSUER_URL} not found in environment')


ensure_required_environment_variables_found()


def fetch_well_known_jwks_from_token_issuer(request_name: str) -> dict:

    response_data = {
        'data': None,
        'code': None,
        'message': 'default'
    }

    LOG.debug(f'Preparing: {request_name}')

    # region Get token issuer url
    _get_token_issuer_url_response = _get_token_issuer_url()

    token_issuer_url = _get_token_issuer_url_response['value']
    _get_token_issuer_url_message = _get_token_issuer_url_response['message']

    if token_issuer_url is None:
        response_data['message'] = _get_token_issuer_url_message
        return response_data
    LOG.debug(_get_token_issuer_url_message)
    # endregion

    request_url = f'{token_issuer_url}/.well-known/jwks.json'
    response_data['requestUrl'] = request_url

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
        response_data['message'] = f'{request_name} failed ({status_code_message})'
        response_data['code'] = response_reason
        return response_data

    LOG.debug(f'{request_name} complete!')
    LOG.debug(status_code_message)

    try:
        response_json = response.json()
    except Exception as err:
        _err_type = type(err).__name__
        _err_text = str(err)
        response_data['code'] = _err_type
        _status_message = f'Response data does not have a valid JSON ({_err_text})'
        response_data['message'] = _status_message
        LOG.warning(_status_message)
        return response_data

    response_data['code'] = 'SUCCESS'
    response_data['data'] = response_json
    _status_text = f'Successfully obtained desired data from {request_name}'
    response_data['message'] = _status_text

    LOG.info(_status_text)

    return response_data


def _get_token_issuer_url() -> dict:

    response_data = {
        'value': None,
        'message': 'default'
    }

    _env_var_name = definitions.ENV_VAR_NAME_TOKEN_ISSUER_URL

    if _env_var_name not in os.environ:
        response_data['message'] = f'variable: {_env_var_name} not found in environment'
        return response_data

    _env_var_value = os.environ[_env_var_name]
    response_data['value'] = _env_var_value
    response_data['message'] = f'Obtained variable from environment: {_env_var_name}'

    return response_data
