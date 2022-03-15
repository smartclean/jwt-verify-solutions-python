import time
import json
from os import getenv
from base64 import b64decode

import jwt

from util import data_ops
from util.logging import get_logger_for_module
from util.jwk_to_pem import convert_to_rsa_public_key
from api.jwt_issuer import fetch_well_known_jwks_from_token_issuer


_LOG_LEVEL = getenv('LOG_LEVEL', 'info')
LOG = get_logger_for_module(__name__, _LOG_LEVEL)


def verify_signed_access_token(token: str, scope: str = None) -> dict:
    """
    Verify the given signed JWT access token JWS token

    :param token:
    :param scope:
    :return:
    """

    LOG.debug('Starting Process...')

    response_data = {
        'code': None,
        'data': None,
        'message': 'default'
    }

    # region 1. Ensure structure of JWT token valid, extract token sections
    _check_structure_resp = _check_jwt_token_structure_valid(token)
    structure_valid = _check_structure_resp['status']
    check_structure_message = _check_structure_resp['message']

    if structure_valid is False:
        response_data['message'] = f'Step 1 failed. {check_structure_message}'
        return response_data

    LOG.debug(check_structure_message)

    token_sections_by_name = _check_structure_resp['token_sections_by_name']
    LOG.debug(f'Extracted desired sections from token: {set(token_sections_by_name.keys())}')
    # endregion

    # region 2. Deserialize token payload
    _base64_encoded_token_payload = token_sections_by_name['payload']
    _deserialize_token_payload_response = _deserialize_base64_encoded_token_section(
        _base64_encoded_token_payload,
        section_name='payload'
    )
    token_payload_data = _deserialize_token_payload_response['data']
    deserialize_token_payload_message = _deserialize_token_payload_response['data']
    if token_payload_data is None:
        response_data['code'] = _deserialize_token_payload_response['code']
        response_data['message'] = deserialize_token_payload_message
        return response_data
    LOG.debug(deserialize_token_payload_message)
    # endregion

    # region 3. Verify token payload claims
    _verify_token_payload_claims_response = _verify_token_payload_claims(
        token_payload_data,
        exp_token_use='access',
        exp_scope=scope
    )

    token_payload_claims_correct = _verify_token_payload_claims_response['status']
    _verify_token_payload_claims_message = _verify_token_payload_claims_response['message']

    if token_payload_claims_correct is False:
        LOG.warning(_verify_token_payload_claims_message)
        response_data['code'] = _verify_token_payload_claims_response['code']
        response_data['message'] = _verify_token_payload_claims_message
        return response_data

    LOG.debug(_verify_token_payload_claims_message)
    # endregion

    # region 4. Deserialize token header
    _base64_encoded_token_header = token_sections_by_name['header']
    _deserialize_token_header_response = _deserialize_base64_encoded_token_section(
        _base64_encoded_token_header,
        section_name='header'
    )
    token_header_data = _deserialize_token_header_response['data']
    deserialize_token_header_message = _deserialize_token_header_response['data']
    if token_header_data is None:
        response_data['code'] = _deserialize_token_header_response['code']
        response_data['message'] = deserialize_token_header_message
        return response_data
    LOG.debug(deserialize_token_header_message)
    # endregion

    # region 5(a). Get kid from token header data
    _get_kid_resp = data_ops.extract_attr_from_dictionary(
        token_header_data,
        'token header data',
        'kid',
        str
    )

    local_kid = _get_kid_resp['value']
    get_kid_text = _get_kid_resp['text']

    if local_kid is None:
        response_data['message'] = get_kid_text
        return response_data
    # endregion

    # region 5(b). Get alg from token header data
    _get_alg_resp = data_ops.extract_attr_from_dictionary(
        token_header_data,
        'token_header_data',
        'alg',
        str
    )

    local_key_alg = _get_alg_resp['value']
    get_alg_text = _get_alg_resp['text']

    if local_key_alg is None:
        response_data['message'] = get_alg_text
        return response_data

    # endregion

    # TODO: Rather in this step, write the data obtained to a file for later access

    # region 6. Get well known JWKS from token_issuer
    jwks_data_source_name = 'well known JWKS from token issuer'

    request_name_get_jwks = f'Get {jwks_data_source_name}'

    get_jwks_response = fetch_well_known_jwks_from_token_issuer(request_name_get_jwks)
    jwks_data = get_jwks_response['data']
    get_jwks_message = get_jwks_response['message']

    if jwks_data is None:
        response_data['code'] = 'FETCH_JWKS_FAILED'
        response_data['message'] = get_jwks_message
        LOG.error(get_jwks_message)
        response_data['data'] = {'requestUrl': get_jwks_response['requestUrl']}

    LOG.debug(get_jwks_message)
    # endregion

    # region 8. Extract "keys" (JWK objects) from JWKS data
    get_jwk_objects_resp = data_ops.extract_attr_from_dictionary(
        data=jwks_data,
        data_name=jwks_data_source_name,
        attr_name='keys',
        exp_type=list
    )

    jwk_objects = get_jwk_objects_resp['value']
    get_jwk_objects_status = get_jwk_objects_resp['text']

    if jwk_objects is None:
        response_data['code'] = 'GET_JWKS_FAILED'
        response_data['message'] = get_jwk_objects_status
        return response_data

    LOG.debug(get_jwk_objects_status)
    # endregion

    # region 9. Get JWK object matching local "kid" and "alg"
    _get_jwk_object_matching_kid_response = _get_jwk_object_matching_kid(local_kid, local_key_alg, jwk_objects)
    matching_jwk_object = _get_jwk_object_matching_kid_response['data']
    _get_jwk_object_matching_kid_message = _get_jwk_object_matching_kid_response['message']

    if matching_jwk_object is None:
        response_data['code'] = 'JWK_MATCHING_FAILED'
        response_data['message'] = _get_jwk_object_matching_kid_message
        return response_data

    LOG.info(_get_jwk_object_matching_kid_message)
    # endregion

    # region 10. Convert JWK object to PEM
    _convert_to_rsa_public_key_response = convert_to_rsa_public_key(matching_jwk_object)

    rsa_public_key = _convert_to_rsa_public_key_response['value']
    _convert_to_rsa_public_key_message = _convert_to_rsa_public_key_response['message']

    if rsa_public_key is None:
        response_data['code'] = 'INVALID_JWK'
        response_data['message'] = f'Convert JWK to Public Key failed ({_convert_to_rsa_public_key_message})'
        return response_data
    LOG.debug(_convert_to_rsa_public_key_message)
    # endregion

    # region Verify token with Public Key and Token Payload
    _verify_jwt_response = verify_jwt_using_public_key(
        token,
        token_payload_data,
        local_key_alg,
        rsa_public_key
    )

    verify_success = _verify_jwt_response['status']
    _verify_jwt_message = _verify_jwt_response['message']

    if verify_success is False:
        response_data['code'] = 'JWT_VERIFICATION_FAILED'
        response_data['message'] = _verify_jwt_message
        return response_data
    # endregion

    # TODO: Next tasks for Dev
    #  Code cleanup (remove all unwanted functions and move utils to where they belong)

    response_data['code'] = 'SUCCESS'
    if response_data['data'] is None:
        response_data.pop('data')
    response_data['message'] = 'JWT verification successful'

    return response_data


# region Utils


def _deserialize_base64_encoded_token_section(base64_encoded_token_section: str, section_name: str) -> dict:

    response_data = {
        'data': None,
        'code': 'default',
        'message': 'default'
    }

    # region Decode section using base64 (fail if invalid base64 string)
    try:
        _b64_decoded_token_section_json_bytes = b64decode(base64_encoded_token_section)
    except Exception as err:
        _err_type = type(err).__name__
        _err_text = str(err)
        err_info = f'Failed to decode token {section_name} using base64 ({_err_text})'
        response_data['code'] = _err_type
        response_data['message'] = err_info
        return response_data
    # endregion

    # region Decode bytes string to json string (fail if not bytes)
    # region Ensure base64 decoded value is bytes
    _type_b64_decoded_token_section = type(_b64_decoded_token_section_json_bytes)

    if _type_b64_decoded_token_section is not bytes:
        response_data['code'] = 'UNEXPECTED_DATA_FORMAT'
        response_data['message'] = f'Expected bytes string on decoding token {section_name} using base64 ' \
                                   f'(Found: {_type_b64_decoded_token_section})'
        return response_data
    # endregion

    _decoded_token_section_json_string = _b64_decoded_token_section_json_bytes.decode('utf-8')
    # endregion

    try:
        decoded_token_section_data = json.loads(_decoded_token_section_json_string)
    except Exception as err:
        _err_text = str(err)
        _err_type = type(err).__name__
        if _err_type == 'json.decoder.JSONDecodeError':
            response_data['code'] = 'JSONDecodeError'
            response_data['message'] = f'Token {section_name} data contains invalid JSON'
        else:
            response_data['code'] = _err_type
            response_data['message'] = f'Failed to JSON decode token {section_name} ({_err_text})'

        return response_data

    response_data['data'] = decoded_token_section_data
    response_data['message'] = f'Decoded and deserialized token {section_name}.'
    return response_data


# region Verify token payload claims
def _verify_token_payload_claims(payload_data: dict, exp_token_use: str, exp_scope: str = None):

    response_data = {
        'code': None,
        'status': False,
        'message': 'default',
    }

    # region 1. Ensure token is not already expired (using payload data)
    current_unix_time_seconds = int(time.time())

    _check_token_expired_resp = _check_token_expired(
        payload_data,
        current_unix_time_seconds
    )

    token_expired = _check_token_expired_resp['status']
    check_token_expired_message = _check_token_expired_resp['message']

    if token_expired is True:
        response_data['code'] = 'TOKEN_EXPIRED'
        response_data['message'] = check_token_expired_message
        return response_data

    LOG.debug(check_token_expired_message)
    # endregion

    # region 2. Ensure token_use claim matches desired value (using payload data)
    _check_token_use_correct = _check_token_use_claim_matches_desired_value(
        payload_data,
        desired_value=exp_token_use
    )
    token_use_correct = _check_token_use_correct['status']
    check_token_use_correct_message = _check_token_use_correct['message']

    if token_use_correct is False:
        response_data['code'] = 'INCORRECT_JWT_CLAIM_TOKEN_USE'
        response_data['message'] = check_token_use_correct_message
        return response_data

    LOG.debug(check_token_use_correct_message)
    # endregion

    # region 3. If expected scope given, Ensure scope in token matches the given value
    if exp_scope is not None:
        _check_token_scope_correct_response = _check_token_scope_matches_desired_value(
            payload_data,
            desired_value=exp_scope
        )
        scope_correct = _check_token_scope_correct_response['status']
        _check_token_scope_correct_message = _check_token_scope_correct_response['message']

        if scope_correct is False:
            response_data['code'] = 'INCORRECT_JWT_CLAIM_SCOPE'
            response_data['message'] = _check_token_scope_correct_message
            return response_data
        LOG.debug(_check_token_scope_correct_message)
    # endregion

    response_data['code'] = 'SUCCESS'
    response_data['status'] = True
    response_data['message'] = 'Token payload claims verified correct.'
    return response_data


def _check_token_expired(token_payload_data: dict, current_unix_time_seconds: int) -> dict:
    """
    Checks whether token expired (using "exp" claim in the token payload data)

    :param token_payload_data:
    :param current_unix_time_seconds:
    :return:
    """

    response_data = {
        'status': True,
        'message': 'default'
    }

    payload_attr_expiry = 'exp'
    data_name = 'token payload data'

    # region Get "exp" (expiry unix time seconds) from token payload data
    _get_exp_resp = data_ops.extract_attr_from_dictionary(
        data=token_payload_data,
        data_name=data_name,
        attr_name=payload_attr_expiry,
        exp_type=int
    )

    expiry_unix_time_seconds = _get_exp_resp['value']
    get_exp_text = _get_exp_resp['text']

    if expiry_unix_time_seconds is None:
        response_data['message'] = f'Failed to check token expiry ({get_exp_text})'
        return response_data

    # endregion

    if expiry_unix_time_seconds < current_unix_time_seconds:
        response_data['message'] = f'Expiry time ({payload_attr_expiry} value) in {data_name} is behind current time'
        return response_data

    response_data['status'] = False
    response_data['message'] = f'Expiry time ({payload_attr_expiry} value) in {data_name} is not behind current time'

    return response_data


def _check_token_use_claim_matches_desired_value(token_payload_data: dict, desired_value: str) -> dict:
    """
    Checks whether "token_use" claim matches the given "desired_value"

    :param token_payload_data:
    :param desired_value:
    :return:
    """

    response_data = {
        'status': False,
        'message': 'default'
    }

    payload_attr_token_use = 'token_use'
    data_name = 'token payload data'

    # region Get "token_use" from token payload data
    _get_token_use_resp = data_ops.extract_attr_from_dictionary(
        data=token_payload_data,
        data_name=data_name,
        attr_name=payload_attr_token_use,
        exp_type=str
    )

    token_use_value = _get_token_use_resp['value']

    get_token_use_message = _get_token_use_resp['text']

    if token_use_value is None:
        response_data['message'] = f'Failed to check token_use({get_token_use_message})'
        return response_data

    # endregion

    if token_use_value != desired_value:
        response_data['message'] = f'{payload_attr_token_use} value in {data_name} is not "{desired_value}"'
        return response_data

    response_data['status'] = True
    response_data['message'] = f'{payload_attr_token_use} value in {data_name} matches "{desired_value}"'

    return response_data


def _check_token_scope_matches_desired_value(token_payload_data: dict, desired_value: str) -> dict:
    """
    Checks whether "scope" claim matches the given "desired_value"

    :param token_payload_data:
    :param desired_value:
    :return:
    """

    response_data = {
        'status': False,
        'message': 'default'
    }

    payload_attr_scope = 'scope'
    data_name = 'token payload data'

    # region Get "scope" from token payload data
    _get_scope_resp = data_ops.extract_attr_from_dictionary(
        data=token_payload_data,
        data_name=data_name,
        attr_name=payload_attr_scope,
        exp_type=str
    )

    scope_value = _get_scope_resp['value']
    get_scope_message = _get_scope_resp['text']

    if scope_value is None:
        response_data['message'] = f'failed token scope check ({get_scope_message})'
        return response_data

    # endregion

    if scope_value != desired_value:
        response_data['message'] = f'{payload_attr_scope} value in {data_name} is not "{desired_value}"'
        return response_data

    response_data['status'] = True
    response_data['message'] = f'{payload_attr_scope} value in {data_name} matches "{desired_value}"'

    return response_data
# endregion


def verify_jwt_using_public_key(jwt_token: str, decoded_token_payload: dict, algorithm: str, public_key: str):

    response_data = {
        'status': False,
        'message': 'default'
    }

    decode_jwt_response = _decode_jwt(
        token=jwt_token,
        public_key=public_key,
        alg=algorithm)

    decoded_jwt_data = decode_jwt_response['data']
    decoded_jwt_message = decode_jwt_response['message']

    if decoded_jwt_data is None:
        response_data['message'] = f'Failed to decode JWT token ({decoded_jwt_message})'
        return response_data

    LOG.debug(decoded_jwt_message)

    if decoded_jwt_data == decoded_token_payload:
        response_data['status'] = True
        response_data['message'] = 'JWT successfully verified using public key'
        return response_data

    response_data['message'] = 'JWT decoded using given public key did not match the given token payload'
    return response_data


def _check_jwt_token_structure_valid(jwt_token: str) -> dict:

    response_data = {
        'status': False,
        'message': 'Structure invalid',
        'token_sections_by_name': None,
        'jwtVerifyStepNumber': 1
    }

    _separating_char = '.'
    required_no_of_sections = 3

    _invalid_status_text = f'token must contain {required_no_of_sections} sections separated by {_separating_char}'

    if _separating_char not in jwt_token:
        response_data['message'] += f' ({_invalid_status_text})'
        return response_data

    _token_sections = jwt_token.split('.')
    no_of_sections = len(_token_sections)

    if no_of_sections != 3:
        response_data['message'] += f' ({_invalid_status_text})'
        return response_data

    token_sections_by_name = {
        'header': _token_sections[0],
        'payload': _token_sections[1],
        'signature': _token_sections[2]
    }

    response_data['token_sections_by_name'] = token_sections_by_name

    response_data['status'] = True
    response_data['message'] = 'Structure valid'
    return response_data


def _get_jwk_object_matching_kid(local_kid: str, local_alg: str, public_jwk_objects: list) -> dict:
    """
    Select JWK object whose "kid" matches given local_kid

    :param local_kid:
    :param local_alg:
    :param public_jwk_objects:
    :return:
    """

    response_data = {
        'data': None,
        'message': 'default'
    }

    no_of_keys_data = len(public_jwk_objects)

    if no_of_keys_data == 1:
        public_jwk_object = public_jwk_objects[0]

        # region Extract kid from public jwk object
        _get_kid_from_public_jwk_obj_response = data_ops.extract_attr_from_dictionary(
            data=public_jwk_object,
            data_name='public jwk object',
            attr_name='kid',
            exp_type=str
        )
        kid_in_public_jwk_object = _get_kid_from_public_jwk_obj_response['value']
        get_kid_from_public_jwk_obj_status = _get_kid_from_public_jwk_obj_response['text']

        if kid_in_public_jwk_object is None:
            response_data['message'] = get_kid_from_public_jwk_obj_status
            return response_data
        LOG.debug(get_kid_from_public_jwk_obj_status)
        # endregion

        if local_kid != kid_in_public_jwk_object:
            response_data['message'] = 'Given "kid" did not match "kid" of this public JWK object'
            return response_data

        _status_text = 'Given "kid" matched "kid" of this public JWK object'
        LOG.info(_status_text)

        # region Extract alg from matched public jwk object
        _get_alg_from_public_jwk_obj_response = data_ops.extract_attr_from_dictionary(
            data=public_jwk_object,
            data_name='public jwk object',
            attr_name='alg',
            exp_type=str
        )

        alg_in_public_jwk_object = _get_alg_from_public_jwk_obj_response['value']
        get_alg_from_public_jwk_obj_status = _get_alg_from_public_jwk_obj_response['text']

        if alg_in_public_jwk_object is None:
            response_data['message'] = get_alg_from_public_jwk_obj_status
            return response_data
        LOG.debug(get_alg_from_public_jwk_obj_status)
        # endregion

        if local_alg != alg_in_public_jwk_object:
            response_data['message'] = 'Given "alg" did not match "alg" of this public JWK object'
            return response_data

        response_data['data'] = public_jwk_object
        response_data['message'] = 'Given "kid" and "alg" matched "kid" and "alg" of this public JWK object'

        return response_data

    for public_jwk_object in public_jwk_objects:

        # region Extract kid from public jwk object
        _get_kid_from_public_jwk_obj_response = data_ops.extract_attr_from_dictionary(
            data=public_jwk_object,
            data_name='public jwk object',
            attr_name='kid',
            exp_type=str
        )
        kid_in_public_jwk_object = _get_kid_from_public_jwk_obj_response['value']
        get_kid_from_public_jwk_obj_status = _get_kid_from_public_jwk_obj_response['text']

        if kid_in_public_jwk_object is None:
            LOG.warning(f'JWK matching Loop: {get_kid_from_public_jwk_obj_status}')
            continue
        LOG.debug(f'JWK matching Loop: {get_kid_from_public_jwk_obj_status}')
        # endregion

        if local_kid != kid_in_public_jwk_object:
            LOG.debug('JWK matching Loop: Given "kid" did not match "kid" of this public JWK object')
            continue

        LOG.info('JWK matching Loop: Given "kid" matched "kid" of this public JWK object')

        # region Extract alg from matched public jwk object
        _get_alg_from_public_jwk_obj_response = data_ops.extract_attr_from_dictionary(
            data=public_jwk_object,
            data_name='public jwk object',
            attr_name='alg',
            exp_type=str
        )

        alg_in_public_jwk_object = _get_alg_from_public_jwk_obj_response['value']
        get_alg_from_public_jwk_obj_status = _get_alg_from_public_jwk_obj_response['text']

        if alg_in_public_jwk_object is None:
            LOG.warning(f'JWK matching Loop: {get_alg_from_public_jwk_obj_status}')
            continue

        LOG.debug(f'JWK matching Loop: {get_alg_from_public_jwk_obj_status}')
        # endregion

        if local_alg != alg_in_public_jwk_object:
            LOG.warning('JWK matching Loop: Given "alg" did not match "alg" of this public JWK object')
            continue

        LOG.info('JWK matching Loop: Given "alg" matched "alg" of this public JWK object')

        response_data['data'] = public_jwk_object
        response_data['message'] = 'Given "kid" and "alg" matched "kid" and "alg" of this public JWK object'

        return response_data

    response_data['message'] = 'None of the given public JWK objects matched given "kid" and "alg"'
    return response_data


def _decode_jwt(token: str, public_key: str, alg: str) -> dict:

    response_data = {
        'data': None,
        'message': 'default'
    }

    try:
        response = jwt.decode(token, public_key, algorithms=[alg])
    except Exception as err:
        _err_type = type(err).__name__
        _err_text = str(err)
        err_info = f'{_err_type} decoding using JWT ({_err_text})'
        response_data['message'] = err_info
        return response_data

    response_data['data'] = response
    response_data['message'] = 'Decoded using JWT and given key and algorithm'
    return response_data
# endregion
