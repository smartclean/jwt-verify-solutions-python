from util.type_check import (
    check_list_is_valid,
    check_dict_is_valid,
    check_string_is_valid,
    check_integer_is_valid,
    check_boolean_is_valid
)


def extract_attr_from_dictionary(data: dict, data_name: str, attr_name: str, exp_type: type) -> dict:

    data_return = {
        'value': None,
        'text': 'default',
        'error': False
    }

    if attr_name not in data:
        data_return['text'] = f'{attr_name} not given in {data_name}.'
        return data_return
    attr_value = data[attr_name]

    data_return['text'] = f'Extracted "{attr_name}" from {data_name}'

    if exp_type is str:
        _check_valid_resp = check_string_is_valid(attr_value)
        _valid = _check_valid_resp['status']
        _valid_status = _check_valid_resp['text']
        if _valid is False:
            data_return['error'] = True
            data_return['text'] += f' but {_valid_status} (Expected string)'
            return data_return
        data_return['value'] = attr_value
        data_return['text'] += f' and checked it is a valid {exp_type.__name__} value'
        return data_return

    if exp_type is dict:
        _check_valid_resp = check_dict_is_valid(attr_value)
        _valid = _check_valid_resp['status']
        _valid_status = _check_valid_resp['text']
        if _valid is False:
            data_return['error'] = True
            data_return['text'] += f' but {_valid_status} (Expected dictionary)'
            return data_return
        data_return['value'] = attr_value
        data_return['text'] = f' and checked it is a valid {exp_type.__name__} value'
        return data_return

    if exp_type is int:
        _check_valid_resp = check_integer_is_valid(attr_value)
        _valid = _check_valid_resp['status']
        _valid_status = _check_valid_resp['text']
        if _valid is False:
            data_return['error'] = True
            data_return['text'] += f' but {_valid_status} (Expected {exp_type.__name__})'
            return data_return
        data_return['value'] = attr_value
        data_return['text'] += f' and checked it is a valid {exp_type.__name__} value'
        return data_return

    if exp_type is list:
        _check_valid_resp = check_list_is_valid(attr_value)
        _valid = _check_valid_resp['status']
        _valid_status = _check_valid_resp['text']
        if _valid is False:
            data_return['error'] = True
            data_return['text'] += f' but {_valid_status} (Expected {exp_type.__name__})'
            return data_return
        data_return['value'] = attr_value
        data_return['text'] = f' and checked it is a valid {exp_type.__name__} value'
        return data_return

    if exp_type is bool:
        _check_valid_resp = check_boolean_is_valid(attr_value)
        _valid = _check_valid_resp['status']
        _valid_status = _check_valid_resp['text']
        if _valid is False:
            data_return['error'] = True
            data_return['text'] += f' but {_valid_status} (Expected {exp_type.__name__})'
            return data_return
        data_return['value'] = attr_value
        data_return['text'] += f' and checked it is a valid {exp_type.__name__} value'
        return data_return

    # TODO: Handle other types as required
    raise Exception('Not Implemented')
