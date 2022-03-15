import definitions

# region Data Definition: Checker functions
_MODEL_CHECKER_DATA_RETURN = definitions.CHECKER_MODEL_DATA_RETURN
_CHECKER_ATTR_TEXT = definitions.CHECKER_ATTR_TEXT
_CHECKER_ATTR_STATUS = definitions.CHECKER_ATTR_STATUS
_CHECKER_ATTR_ERROR = definitions.CHECKER_ATTR_STATUS
# endregion


def check_string_is_valid(value: any) -> _MODEL_CHECKER_DATA_RETURN:

    data_return = _MODEL_CHECKER_DATA_RETURN.copy()

    type_value = type(value)
    if type_value != str:
        data_return[_CHECKER_ATTR_TEXT] = f'given type: {type_value.__name__}'
        return data_return

    attr_value_status = f'value is: {value}'

    if value == '' or value == 'null':
        data_return[_CHECKER_ATTR_TEXT] = attr_value_status
        return data_return

    data_return['status'] = True
    data_return['text'] = 'given valid string'
    return data_return


def check_boolean_is_valid(value: any) -> _MODEL_CHECKER_DATA_RETURN:

    data_return = _MODEL_CHECKER_DATA_RETURN.copy()

    type_value = type(value)
    if type_value != bool:
        data_return[_CHECKER_ATTR_TEXT] = f'given value has type: {type_value.__name__}'
        return data_return

    data_return['status'] = True
    data_return['text'] = 'given value is a valid boolean'
    return data_return


def check_integer_is_valid(value: any) -> _MODEL_CHECKER_DATA_RETURN:

    data_return = _MODEL_CHECKER_DATA_RETURN.copy()

    type_value = type(value)
    if type_value != int:
        data_return[_CHECKER_ATTR_TEXT] = f'given value has type: {type_value.__name__}'
        return data_return

    data_return['status'] = True
    data_return['text'] = 'given value is a valid integer'
    return data_return


def check_dict_is_valid(value: any) -> _MODEL_CHECKER_DATA_RETURN:

    data_return = _MODEL_CHECKER_DATA_RETURN.copy()

    type_value = type(value)
    if type_value != dict:
        data_return[_CHECKER_ATTR_TEXT] = f'given value has type: {type_value.__name__}'
        return data_return

    if not value:
        data_return[_CHECKER_ATTR_TEXT] = 'given value is empty dictionary'
        return data_return

    data_return[_CHECKER_ATTR_STATUS] = True
    data_return[_CHECKER_ATTR_TEXT] = 'given value is valid dictionary'
    return data_return


def check_list_is_valid(value: any) -> _MODEL_CHECKER_DATA_RETURN:

    data_return = _MODEL_CHECKER_DATA_RETURN.copy()

    type_value = type(value)
    if type_value != list:
        data_return[_CHECKER_ATTR_TEXT] = f'given value has type: {type_value.__name__}'
        return data_return

    if not value:
        data_return[_CHECKER_ATTR_TEXT] = 'given value is empty list'
        return data_return

    data_return[_CHECKER_ATTR_STATUS] = True
    data_return[_CHECKER_ATTR_TEXT] = 'given value is valid list'
    return data_return


# def extract_attr_from_dictionary(data: dict, data_name: str, attr_name: str, exp_type: type) -> dict:
#
#     data_return = {
#         'value': None,
#         'text': 'default',
#         'error': False
#     }
#
#     if attr_name not in data:
#         data_return['text'] = f'{attr_name} not given in {data_name}.'
#         return data_return
#     attr_value = data[attr_name]
#
#     data_return['text'] = f'Extracted "{attr_name}" from {data_name}'
#
#     if exp_type is str:
#         _check_valid_resp = _check_string_is_valid(attr_value)
#         _valid = _check_valid_resp['status']
#         _valid_status = _check_valid_resp['text']
#         if _valid is False:
#             data_return['error'] = True
#             data_return['text'] += f' but {_valid_status} (Expected string)'
#             return data_return
#         data_return['value'] = attr_value
#         data_return['text'] += f' and checked it is a valid {exp_type.__name__} value'
#         return data_return
#
#     if exp_type is dict:
#         _check_valid_resp = check_dict_is_valid(attr_value)
#         _valid = _check_valid_resp['status']
#         _valid_status = _check_valid_resp['text']
#         if _valid is False:
#             data_return['error'] = True
#             data_return['text'] += f' but {_valid_status} (Expected dictionary)'
#             return data_return
#         data_return['value'] = attr_value
#         data_return['text'] = f' and checked it is a valid {exp_type.__name__} value'
#         return data_return
#
#     if exp_type is int:
#         _check_valid_resp = _check_integer_is_valid(attr_value)
#         _valid = _check_valid_resp['status']
#         _valid_status = _check_valid_resp['text']
#         if _valid is False:
#             data_return['error'] = True
#             data_return['text'] += f' but {_valid_status} (Expected {exp_type.__name__})'
#             return data_return
#         data_return['value'] = attr_value
#         data_return['text'] += f' and checked it is a valid {exp_type.__name__} value'
#         return data_return
#
#     if exp_type is list:
#         _check_valid_resp = _check_list_is_valid(attr_value)
#         _valid = _check_valid_resp['status']
#         _valid_status = _check_valid_resp['text']
#         if _valid is False:
#             data_return['error'] = True
#             data_return['text'] += f' but {_valid_status} (Expected {exp_type.__name__})'
#             return data_return
#         data_return['value'] = attr_value
#         data_return['text'] = f' and checked it is a valid {exp_type.__name__} value'
#         return data_return
#
#     if exp_type is bool:
#         _check_valid_resp = _check_boolean_is_valid(attr_value)
#         _valid = _check_valid_resp['status']
#         _valid_status = _check_valid_resp['text']
#         if _valid is False:
#             data_return['error'] = True
#             data_return['text'] += f' but {_valid_status} (Expected {exp_type.__name__})'
#             return data_return
#         data_return['value'] = attr_value
#         data_return['text'] += f' and checked it is a valid {exp_type.__name__} value'
#         return data_return
#
#     # TODO: Handle other types as required
#     raise Exception('Not Implemented')
