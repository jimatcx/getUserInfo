# getUserInfo
Creates a CSV file containing user information and resolving the:
- Roles
- Teams
- Authentication Provider information

Optionally, this will create a file mapping Roles to specific Permissions

Python requirements are
- python 3

The following modules are needed:
- `pip install argparse`
- `pip install json`
- `pip install csv`
- `pip install configparser`


Included is a sample 'config.ini' file.  The default location for this is in your "`home directory/.Checkmarx/`"

The usage is:

`>getUserInfo.py`

optional arguments:

  `-h, --help            show this help message and exit`

  `-c CONFIG, --config CONFIG
                        The config.ini location if not in the default place`

  `-f FILE, --file FILE  The name of the CSV file to put the user output. Default is userData.csv`

  `-r ROLES, --roles ROLES
                        The name of the CSV file to put the permissions to role mapping. If not specified, that
                        mapping will not be performed.`

`  -v                    Verbosity level for console output. Default is none.`
