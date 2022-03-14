import os
from pprint import pformat
from dotenv import load_dotenv

import definitions


def load_env_vars_from_file():

    _absolute_path_project_directory = os.path.dirname(os.path.abspath(__name__))
    print(f'Absolute path to Project directory is:\n{_absolute_path_project_directory}')

    _project_relative_path_to_env_file = definitions.PROJECT_RELATIVE_PATH_TO_ENVIRONMENT_FILE
    print(f'definition: PROJECT_RELATIVE_PATH_TO_ENVIRONMENT_FILE is:\n{_project_relative_path_to_env_file}')

    path_to_environment_file = f'{_absolute_path_project_directory}/{_project_relative_path_to_env_file}'
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


def run_main(access_token: str):

    import main
    response = main.do(access_token)
    print('Response is:')
    print(pformat(response))


if __name__ == '__main__':
    access_token = None  # Paste access token here to test

    load_env_vars_from_file()
    run_main(access_token)
