import os
import base64
import json

from util.logging import get_logger_for_module
from util import data_ops
from api.amazon_cognito import get_jwks_json_for_user_pool

from pprint import pformat

_LOG_LEVEL = os.getenv('LOG_LEVEL', 'info')
LOG = get_logger_for_module(__name__, _LOG_LEVEL)


def do(jwt_access_token: str) -> dict:

    LOG.debug('Starting Process...')

    response_data = {
        'code': None,
        'data': None,
        'message': 'default'
    }

    # region 1. Fetch well known JWKS for desired AWS Cognito User Pool
    request_name_get_jwks = 'Get well known JWKS for AWS Cognito User Pool'

    get_jwks_response = get_jwks_json_for_user_pool(request_name_get_jwks)
    jwks_data = get_jwks_response['data']
    get_jwks_message = get_jwks_response['message']

    if jwks_data is None:
        response_data['code'] = 'FETCH_JWKS_FAILED'
        response_data['message'] = get_jwks_message
        LOG.error(get_jwks_message)
        response_data['data'] = {'requestUrl': get_jwks_response['requestUrl']}

    LOG.debug(get_jwks_message)
    # endregion

    response_data['code'] = 'TOKEN_INVALID'

    # region 2. Check structure valid
    _check_structure_resp = _check_jwt_token_structure_valid(jwt_access_token)
    structure_valid = _check_structure_resp['status']
    check_structure_message = _check_structure_resp['message']
    # process_step_number = _check_structure_resp['jwtVerifyStepNumber']

    if structure_valid is False:
        response_data['message'] = f'Step 1 failed. {check_structure_message}'
        return response_data
    # endregion

    token_sections_by_name = _check_structure_resp['token_sections_by_name']

    token_header = token_sections_by_name['header']

    # region base64 Decode token header
    _decoded_token_header_bytes = base64.b64decode(token_header)
    _decoded_token_header_data_json_string = _decoded_token_header_bytes.decode('utf-8')
    decoded_token_header_data = json.loads(_decoded_token_header_data_json_string)
    # endregion

    # region Get kid from decoded token header data
    _get_kid_resp = data_ops.extract_attr_from_dictionary(
        decoded_token_header_data,
        'decoded jwt header',
        'kid',
        str
    )

    local_kid = _get_kid_resp['value']
    get_kid_text = _get_kid_resp['text']

    if local_kid is None:
        response_data['message'] = get_kid_text
        return response_data
    # endregion

    # region Get alg from decoded token header data
    _get_alg_resp = data_ops.extract_attr_from_dictionary(
        decoded_token_header_data,
        'decoded jwt header',
        'alg',
        str
    )

    local_key_alg = _get_alg_resp['value']
    get_alg_text = _get_alg_resp['text']

    if local_key_alg is None:
        response_data['message'] = get_alg_text
        return response_data

    # endregion

    jwks_data_name = 'well known JWKS for AWS Cognito User Pool'

    get_jwks_objects_resp = data_ops.extract_attr_from_dictionary(
        data=jwks_data,
        data_name=jwks_data_name,
        attr_name='keys',
        exp_type=list
    )

    jwks_objects = get_jwks_objects_resp['value']
    get_jwks_objects_status = get_jwks_objects_resp['text']

    # region Check header key id matches public key id

    _check_header_key_id_valid_resp = _check_header_kid_matches_any_jwk(local_kid, local_key_alg, )
    key_valid = _check_header_key_id_valid_resp['status']
    check_key_valid_message = _check_header_key_id_valid_resp['message']

    if key_valid is False:
        response_data['message'] = f'Step 3 failed. {check_key_valid_message}'
        return response_data

    # endregion
    token_public_key = _check_header_key_id_valid_resp['public_key']


    # region 2. Check given token matches with any JWK (from well known JWKS for desired cognito user pool)
    # endregion

    # region 2. Convert desired JWKS to PEM format
    # request_name_get_jwks = 'Get well known JWKS for an AWS Cognito User Pool'
    #
    # get_jwks_response = get_jwks_json_for_user_pool(request_name_get_jwks)
    # jwks_data = get_jwks_response['data']
    # get_jwks_message = get_jwks_response['message']
    #
    # if jwks_data is None:
    #     response_data['code'] = 'REQUEST'
    #     response_data['message'] = get_jwks_message
    #     LOG.error(get_jwks_message)
    #     response_data['data'] = {'requestUrl': get_jwks_response['requestUrl']}
    #
    # LOG.debug(get_jwks_message)
    # endregion

    return response_data


def check_jwt_valid(jwt_token: str = None) -> dict:

    response_data = {
        'status': False,
        'code': 'TOKEN_INVALID',
        'error': 'False',
        'message': 'default'
    }

    # region Check structure valid
    _check_structure_resp = _check_jwt_token_structure_valid(jwt_token)
    structure_valid = _check_structure_resp['status']
    check_structure_message = _check_structure_resp['message']
    # process_step_number = _check_structure_resp['jwtVerifyStepNumber']

    if structure_valid is False:
        response_data['message'] = f'Step 1 failed. {check_structure_message}'
        return response_data
    # endregion

    token_sections_by_name = _check_structure_resp['token_sections_by_name']

    # region Check signature section valid
    # _check_signature_resp = _check_jwt_signature_valid(token_signature_b64_string)
    # signature_valid = _check_signature_resp['status']
    # check_signature_message = _check_signature_resp['message']
    #
    # if structure_valid is False:
    #     response_data['message'] = f'Step 2 failed. {check_signature_message}'
    #     return response_data
    # endregion

    token_header = token_sections_by_name['header']

    # region Decode token header
    _decoded_token_header_bytes = base64.b64decode(token_header)
    _decoded_token_header_data_json_string = _decoded_token_header_bytes.decode('utf-8')
    decoded_token_header_data = json.loads(_decoded_token_header_data_json_string)
    # endregion

    # region Get kid from decoded token header data
    _get_kid_resp = data_ops.extract_attr_from_dictionary(
        decoded_token_header_data,
        'decoded jwt header',
        'kid',
        str
    )

    local_kid = _get_kid_resp['value']
    get_kid_text = _get_kid_resp['text']

    if local_kid is None:
        response_data['message'] = get_kid_text
        return response_data
    # endregion

    # region Get alg from decoded token header data
    _get_alg_resp = data_ops.extract_attr_from_dictionary(
        decoded_token_header_data,
        'decoded jwt header',
        'alg',
        str
    )

    local_key_alg = _get_alg_resp['value']
    get_alg_text = _get_alg_resp['text']

    if local_key_alg is None:
        response_data['message'] = get_alg_text
        return response_data

    # endregion

    # region Check header key id matches public key id

    _check_header_key_id_valid_resp = _check_header_kid_matches_any_public_key(local_kid, local_key_alg)
    key_valid = _check_header_key_id_valid_resp['status']
    check_key_valid_message = _check_header_key_id_valid_resp['message']

    if key_valid is False:
        response_data['message'] = f'Step 3 failed. {check_key_valid_message}'
        return response_data

    # endregion
    token_public_key = _check_header_key_id_valid_resp['public_key']

    token_payload = token_sections_by_name['payload']

    # region Decode token payload
    _decoded_token_payload_bytes = base64.b64decode(token_payload)
    _decoded_token_payload_data_json_string = _decoded_token_payload_bytes.decode('utf-8')
    decoded_token_payload_data = json.loads(_decoded_token_payload_data_json_string)
    # endregion

    # region Get exp from decoded token payload data
    _get_exp_resp = utils.extract_attr_from_dictionary(
        decoded_token_payload_data,
        'decoded jwt payload',
        'exp',
        int
    )

    token_exp = _get_exp_resp['value']
    get_exp_text = _get_exp_resp['text']

    if token_exp is None:
        response_data['message'] = get_exp_text
        return response_data

    # endregion

    curr_unix_time = int(time())

    if token_exp < curr_unix_time:
        response_data['message'] = 'Given token has already expired'
        return response_data

    # region Get token_use from decoded token payload data
    _get_token_use_resp = utils.extract_attr_from_dictionary(
        decoded_token_payload_data,
        'decoded jwt payload',
        'token_use',
        str
    )

    token_use = _get_token_use_resp['value']
    get_token_use_text = _get_token_use_resp['text']

    if token_use is None:
        response_data['message'] = get_token_use_text
        return response_data

    # endregion

    if token_use != 'access':
        response_data['message'] = f'token_use in decoded token payload is: {token_use} (Required: "access")'
        return response_data

    # region Get iat from decoded token payload data
    _get_iat_resp = utils.extract_attr_from_dictionary(
        decoded_token_payload_data,
        'decoded jwt payload',
        'iat',
        int
    )

    token_iat = _get_iat_resp['value']
    get_iat_text = _get_iat_resp['text']

    if token_iat is None:
        response_data['message'] = get_iat_text
        return response_data

    # endregion

    if token_iat > curr_unix_time:
        response_data['message'] = f'UNEXPECTED: iat in token payload is greater than current unix time'
        return response_data

    # region Get client_id from decoded token payload data
    _get_client_id_resp = utils.extract_attr_from_dictionary(
        decoded_token_payload_data,
        'decoded jwt payload',
        'client_id',
        str
    )

    token_client_id = _get_client_id_resp['value']
    get_client_id_text = _get_client_id_resp['text']

    if token_client_id is None:
        response_data['message'] = get_client_id_text
        return response_data

    # endregion

    # TODO: Require client id to verify with token client id...

    # region Get scope from decoded token payload data
    _get_scope_resp = utils.extract_attr_from_dictionary(
        decoded_token_payload_data,
        'decoded jwt payload',
        'scope',
        str
    )

    token_scope = _get_scope_resp['value']
    get_scope_text = _get_scope_resp['text']

    if token_scope is None:
        response_data['message'] = get_scope_text
        return response_data

    # endregion

    decode_jwt_response = _decode_jwt(token=jwt_token, public_key=token_public_key, alg=local_key_alg)

    decoded_jwt_data = decode_jwt_response['data']
    decoded_jwt_message = decode_jwt_response['message']

    if decoded_jwt_data is None:
        response_data['message'] = f'Failed to decode JWT token ({decoded_jwt_message})'
        return response_data

    # Match decoded jwt data with payload

    if decoded_jwt_data == decoded_token_payload_data:
        response_data['status'] = True
        response_data['code'] = 'SUCCESS'
        response_data['message'] = 'JWT token is valid'
        return response_data

    response_data['message'] = 'JWT token is invalid (signature matching failed)'
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


def _check_header_kid_matches_any_jwk(local_kid: str, kid_alg: str = 'RS256', jwk_objects: list) -> dict:
    """
    Compare the local key ID (kid) to the public kid.

    :param kid:
    :param kid_alg:
    :param json_filepath_jwt_keys:
    :return:
    """

    response_data = {
        'status': False,
        'message': 'default',
        'jwtVerifyStepNumber': 3,
        'public_key': None
    }

    # region Get keys data from the public jwt keys json file
    # _file_data_name = 'public jwt keys json file'
    #
    # get_data_response = _get_data_from_jwt_keys_json_file(json_filepath_jwt_keys)
    # json_file_data = get_data_response['data']
    # get_json_file_message = get_data_response['message']
    #
    # if not json_file_data:
    #     response_data['message'] = f'Failed to get data from {_file_data_name} ({get_json_file_message})'
    #     return response_data
    #
    # if 'keys' not in json_file_data:
    #     response_data['message'] = f'Required attribute: "keys" missing in {_file_data_name}'
    #     return response_data
    # endregion

    # jwk_objects = json_file_data['keys']

    # region Ensure keys in data is list
    _type_keys_data = type(jwk_objects)

    if _type_keys_data is not list:
        response_data['message'] = f'"keys" in {_file_data_name} must be list (but found: {_type_keys_data.__name__}'
        return response_data
    # endregion

    no_of_keys_data = len(jwk_objects)

    # region If no of keys in public jwt keys json file is 1 - do matching
    if no_of_keys_data == 1:
        key_data = jwk_objects[0]
        _get_kid_resp = utils.extract_attr_from_data(key_data, 'key data', 'kid', str)
        public_kid = _get_kid_resp['value']
        get_kid_text = _get_kid_resp['text']

        if public_kid is None:
            response_data['message'] = f'Failed to get kid from {_file_data_name} ({get_kid_text})'
            return response_data

        if local_kid == public_kid:
            response_data['status'] = True
            response_data['message'] = 'Local kid matched public kid'
        else:
            response_data['message'] = 'Local kid did not match public kid'

        return response_data
    # endregion

    # region Get public keys data matching "alg" of given key - return if none match
    _get_jwt_public_keys_matching_alg_resp = _get_jwt_public_keys_matching_alg(
        jwk_objects,
        alg_value=kid_alg
    )

    keys_data_matching_alg = _get_jwt_public_keys_matching_alg_resp['data']
    get_jwt_public_keys_matching_alg_message = _get_jwt_public_keys_matching_alg_resp['message']

    if keys_data_matching_alg is None:
        response_data['message'] = get_jwt_public_keys_matching_alg_message
        return response_data
    # endregion

    if len(keys_data_matching_alg) == 1:
        key_data = keys_data_matching_alg[0]

        _get_kid_resp = utils.extract_attr_from_data(key_data, 'public key data', 'kid', str)
        public_kid = _get_kid_resp['value']
        get_kid_text = _get_kid_resp['text']

        if public_kid is None:
            response_data['message'] = f'Failed to get kid from {_file_data_name} ({get_kid_text})'
            return response_data

        if local_kid == public_kid:
            response_data['status'] = True
            response_data['message'] = 'Local kid matched a public kid'

            # region Get public key from public kid data
            _get_public_key_resp = utils.extract_attr_from_data(
                key_data,
                'public key data',
                'n',
                str
            )

            token_public_key = _get_public_key_resp['value']
            get_public_key_text = _get_public_key_resp['text']

            if token_public_key is None:
                response_data['message'] = get_public_key_text
                return response_data

            # endregion
            response_data['public_key'] = token_public_key

        else:
            response_data['message'] = 'Local kid did not match public kid'

        return response_data
    else:
        for key_data in keys_data_matching_alg:

            _get_kid_resp = utils.extract_attr_from_data(key_data, 'key data', 'kid', str)
            public_kid = _get_kid_resp['value']
            get_kid_text = _get_kid_resp['text']

            if public_kid is None:
                print(f'Failed to get kid from {_file_data_name} ({get_kid_text})')
                continue

            if local_kid == public_kid:
                response_data['status'] = True
                response_data['message'] = 'Local kid matched a public kid'

                # region Get public key from public kid data
                _get_public_key_resp = utils.extract_attr_from_data(
                    key_data,
                    'public key data',
                    'n',
                    str
                )

                token_public_key = _get_public_key_resp['value']
                get_public_key_text = _get_public_key_resp['text']

                if token_public_key is None:
                    response_data['message'] = get_public_key_text
                    return response_data

                # endregion
                response_data['public_key'] = token_public_key

                return response_data
        response_data['message'] = f'local kid did not match any of the public kid having alg = {kid_alg}'
        return response_data
