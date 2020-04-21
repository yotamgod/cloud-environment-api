import json
import argparse
import logging
from collections import defaultdict
from flask import Flask, request, abort, Response
from utils import StatRecorder

app = Flask(__name__)

vm_id_to_attackers = {}


class EnvironmentJsonFileError(Exception):
    """
    An exception for when there was an error trying to open the json file supplied to the server.
    """
    pass


def populate_vm_id_to_attackers(environment_json: dict, tag_to_vm_ids: dict, dest_tag_to_source_tags: dict):
    """
    Using the environment_json and two helper lists, creates a dict of vm_id -> potential attackers,
    which is stored in a global variable.

    :param environment_json: the list object representing the json supplied to the server.
    :param tag_to_vm_ids: tags -> vm_ids who have them
    :param dest_tag_to_source_tags: dest_tags -> all source_tags
    """
    global vm_id_to_attackers

    for vm in environment_json['vms']:
        threatening_source_tags = []
        for tag in vm['tags']:
            threatening_source_tags += dest_tag_to_source_tags[tag]

        vm_id_to_attackers[vm['vm_id']] = set()

        for tag in threatening_source_tags:
            vm_id_to_attackers[vm['vm_id']].update(tag_to_vm_ids[tag])


def parse_environment_json(environment_json: dict):
    """
    Extracts the information from the json supplied to the server, in a quick and easily accessible way.
    The method goes over each list (firewall rules and vms) once, and creates helper dictionaries, to allow better
    and fast access to info.
    Eventually a list of vm_id -> potential attacker is created and stored in a global variable.
    (This is to avoid going over the environment many times, and trying to keep good timing.)

    :param environment_json: the list object representing the json supplied to the server.
    """

    logging.info('Parsing environment json.'
                 'There are {} vms and {} firewall rules'.format(len(environment_json['vms']),
                                                                 len(environment_json['fw_rules'])))
    tag_to_vm_ids = defaultdict(set)
    dest_tag_to_source_tags = defaultdict(set)

    for vm in environment_json['vms']:
        for tag in vm['tags']:
            tag_to_vm_ids[tag].add(vm['vm_id'])
    for fw_rule in environment_json['fw_rules']:
        dest_tag_to_source_tags[fw_rule['dest_tag']].add(fw_rule['source_tag'])

    populate_vm_id_to_attackers(environment_json, tag_to_vm_ids, dest_tag_to_source_tags)
    logging.info('Finished parsing environment json.')


def extract_environment_json() -> dict:
    """
    Extracts the json of the environment according to the parameters specified,
    and returns it as a dict.
    """
    parser = argparse.ArgumentParser(description='Cloud machine and firewall api')
    parser.add_argument('json_path', help='Cloud environment json path')
    args = parser.parse_args()
    try:
        with open(args.json_path) as f:
            logging.info('Loading json from supplied file.')
            environment_json = json.load(f)
        return environment_json

    except (IOError, json.JSONDecodeError):
        raise EnvironmentJsonFileError()


@app.before_first_request
def load_cloud_environment():
    """
    Starts the reading and parsing of the cloud environment file-path argument.
    """
    try:
        parse_environment_json(extract_environment_json())
    except EnvironmentJsonFileError:
        logging.exception('There was an error while extracting the environment json. Quitting.')
        exit()


@app.route('/api/v1/attack')
@StatRecorder.method_recorder
def attack() -> str:
    """
    Informs the user of the vms that have the capability of attacking a specified vm.
    Returns a stringified list of the vm_id's.
    """

    vm_id = request.args.get('vm_id')

    try:
        threatening_vms = str(list(vm_id_to_attackers[vm_id]))
    except KeyError:
        logging.info('Vm_id not found in environment: {}'.format(vm_id))
        abort(Response('Vm_id not found.'))

    logging.debug('Attack response: {}'.format(threatening_vms))
    return threatening_vms


@app.route('/api/v1/stats')
def stats() -> str:
    """
    Returns the status of the server. This includes -
    * Number of vm's in the environment
    * Number of requests to the server (successful ones)
    * Average time it took to return the threatening vms.

    """
    attack_stats = StatRecorder.get_method_stats(attack.__name__)
    average_request_time = 'N/A' if not attack_stats['method_count'] \
        else attack_stats['total_method_time'] / attack_stats['method_count']

    stats_response = json.dumps({
        'vm_count': len(vm_id_to_attackers),
        'request_count': attack_stats['method_count'],
        'average_request_time': average_request_time
    })

    logging.debug('Stats response: {}'.format(stats_response))
    return stats_response


if __name__ == '__main__':
    logging.basicConfig(filename='log.log', level=logging.INFO, format='%(levelname)s - %(asctime)s - %(message)s')
    load_cloud_environment()
    app.run()
