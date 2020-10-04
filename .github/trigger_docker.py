# Launch Docker CI when committing
# Inspired from https://medium.com/@zypherman/my-experiences-with-travis-ci-7f5ea26a87c0

import requests
import json
import time
import sys
import logging
import pprint
import os

LOG_LEVEL = logging.INFO

logging.getLogger().addHandler(logging.StreamHandler())
logging.getLogger().setLevel(LOG_LEVEL)
logger = logging.getLogger(__name__)


AUTH_TOKEN = os.getenv("TRAVIS_TOKEN", sys.argv[1] if len(sys.argv) > 1 else None)

if not AUTH_TOKEN:
    logger.error("No token found!")
    sys.exit(1)

LIEF_ID   = 12579556
DOCKER_ID = 15139981

ENDPOINT = 'https://api.travis-ci.org'

LIEF   = f"{ENDPOINT}/repo/{LIEF_ID}"
DOCKER = f"{ENDPOINT}/repo/{DOCKER_ID}"

DOCKER_ENV_VARS_ENDPOINT = f"{DOCKER}/env_vars"

headers = {
    'Content-Type':       'application/json',
    'Accept':             'application/json',
    'User-Agent':         'API Explorer',
    'Travis-API-Version': '3',
    'Authorization':      f'token {AUTH_TOKEN}'
}

def last_docker_build():
    response = requests.get(f"{DOCKER}/branch/master", headers=headers)

    if not response.ok:
        logging.error("Error while getting last_docker_build")
        sys.exit(1)

    href = response.json()["last_build"]["@href"]
    build_info = requests.get(f"{ENDPOINT}{href}", headers=headers)

    if not build_info.ok:
        logging.error("Error while getting build_info")
        sys.exit(1)

    return build_info.json()



def trigger_build():
    response = requests.get(f"{DOCKER}/branch/master", headers=headers)
    build_info = last_docker_build()

    pprint.pprint(build_info)

    # Get last build info
    last_build_id     = build_info["id"]
    last_build_status = build_info["state"]

    # Create env variables
    env_vars = [
        {
            "env_var.name": "TRIGGER_COMMIT",
            "env_var.value": os.getenv("TRAVIS_COMMIT"),
            "env_var.public": False,
        },
        {
            "env_var.name": "TRIGGER_REPO",
            "env_var.value": os.getenv("TRAVIS_REPO_SLUG"),
            "env_var.public": False,
        },
        {
            "env_var.name": "TRIGGER_ACTION",
            "env_var.value": "build-doc",
            "env_var.public": False,
        },
        {
            "env_var.name": "DEPENDENT_BUILD",
            "env_var.value": "true",
            "env_var.public": False,
        },
    ]

    env_vars_results = requests.get(DOCKER_ENV_VARS_ENDPOINT, headers=headers)
    if not env_vars_results.ok:
        logger.error("Error while getting Docker env variables")
        sys.exit(1)
    env_vars_remote = env_vars_results.json()["env_vars"]

    # Set env variables
    for env_var in env_vars:
        remote_var = next(filter(lambda v : v["name"] == env_var["env_var.name"], env_vars_remote), None)
        if remote_var:
            r = requests.patch(f"{DOCKER}/env_var/{remote_var['id']}", data=json.dumps(env_var), headers=headers)
            if not r.ok:
                logger.error(f"Error while setting variable: '{remote_var['name']}'")
                sys.exit(1)
        else:
            result = requests.post(DOCKER_ENV_VARS_ENDPOINT, data=json.dumps(env_var), headers=headers)
            if not result.ok:
                logger.error(f"Error while setting variable: '{env_var['env_var.name']}'")
                sys.exit(1)

    # (Re)Start build
    result = requests.post(f"{ENDPOINT}/build/{last_build_id}/restart", headers=headers)
    if not result.ok:
        logger.error("Error while restarting the build")
        sys.exit(1)

    return 0



def main():
    is_pull_request = not (os.getenv("TRAVIS_PULL_REQUEST", "false") == "false")

    if is_pull_request:
        logger.info("Skipping pull request build...")
        return 0

    return trigger_build()




if __name__ == "__main__":
    sys.exit(main())
