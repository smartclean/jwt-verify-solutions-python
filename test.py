import os
import sys
from pprint import pformat
from dotenv import load_dotenv

import definitions
from util.logger import get_logger_for_module

_LOG_LEVEL = os.getenv('LOG_LEVEL', 'debug')
LOG = get_logger_for_module(__name__, _LOG_LEVEL)


def test_main(access_token: str, scope: str = None):

    LOG.debug('Starting test for main.py')
    _load_env_vars_from_file()

    import main
    response = main.verify_signed_access_token(access_token, scope)
    LOG.info(f'Test complete, Response is:\n{pformat(response)}')


def _load_env_vars_from_file():

    LOG.debug('Loading env vars from file...')

    _absolute_path_project_directory = os.path.dirname(os.path.abspath(__name__))
    LOG.debug(f'Absolute path to Project directory is:\n{_absolute_path_project_directory}')

    _project_relative_path_to_env_file = definitions.PROJECT_RELATIVE_PATH_TO_ENVIRONMENT_FILE
    LOG.debug(f'definition: PROJECT_RELATIVE_PATH_TO_ENVIRONMENT_FILE is: {_project_relative_path_to_env_file}')

    path_to_environment_file = f'{_absolute_path_project_directory}/{_project_relative_path_to_env_file}'
    LOG.debug(f'Absolute path to environment file is:\n{path_to_environment_file}')

    if os.path.isfile(path_to_environment_file) is False:
        raise FileNotFoundError(f'Tip: Please create the file or update the definition: '
                                f'"PROJECT_RELATIVE_PATH_TO_ENVIRONMENT_FILE" (File not found at path:'
                                f'\n{path_to_environment_file})')

    load_response = load_dotenv(path_to_environment_file)

    if load_response is True:
        LOG.info(f'Successfully loaded environment variables from file:\n{path_to_environment_file}')
    else:
        raise Exception(f'Failed to load environment variables from file:\n{path_to_environment_file}')


if __name__ == '__main__':
    print('Received command to run test.py\n')

    access_token = input('Please paste the JWT access token and hit enter...')

    if access_token == '':
        print('No access token given!', file=sys.stderr)

    scope = input('Please enter the scope (optional) and hit enter. Just hit enter to omit scope check.')

    if scope == '':
        print('Scope not given. scope verification will be omitted')
        test_main(access_token)
    else:
        test_main(access_token, scope)

