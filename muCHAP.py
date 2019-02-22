import codecs
import threading
from enum import Enum
import random
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import sys

# identities/secrets

users = {'gordon': 'freeman', 'manny': 'calavera', 'andrew': 'ryan'}


# General purpose

def log(do, msg):
    if do:
        print(msg)


def format_octet(byte_array):
    return ''.join(format(x, '02x') for x in byte_array)


def print_users():
    print("*********************")
    print("Available identities:")
    print("User / Password")
    for user, pss in users.items():
        print(user, "/", pss)
    print("*********************")


# Parsers:

def parse_role(string):
    return string in ["peer", "authenticator"], string, "The role must me peer or authenticator"


def parse_min_len(string):
    return len(string) >= 1, string, "The field must be at least 1 character long"


def do_nothing(string):
    return True, string, ''


def parse_boolean(string):
    if string == "yes":
        return True, True, ""
    elif string == "no":
        return True, False, ""
    else:
        return False, string, "Must be a 'yes' or a 'no'"


def parse_ipv4(string):
    pattern = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return pattern.match(string), string, "An Ipv4 address must have xxx.xxx.xxx.xxx format"


def parse_integer(string):
    try:
        return True, int(string), ""
    except ValueError:
        return False, string, "An integer is required"


def parse_u_integer(string):
    try:
        i = int(string)
        return i >= 0, i, "The value can't be negative"
    except ValueError:
        return False, string, "An integer is required"


class Parser(Enum):
    none = do_nothing
    IP = parse_ipv4
    integer = parse_integer
    positive_int = parse_u_integer
    min_len = parse_min_len
    role = parse_role
    boolean = parse_boolean


# Generators

class IDGen(object):
    id = 0x00
    lock = threading.RLock()

    @staticmethod
    def next():
        IDGen.id = (IDGen.id + 0x01) % 0xFF
        return IDGen.id.to_bytes(1, byteorder='big', signed=False)


def gen_challenge():
    return sha256(bytearray(random.sample(range(256), 256))).digest()


# Prompts/Configuration:


def simple_prompt(message, parser=Parser.none):
    correct = False
    result = None
    while not correct:
        result = input(message)
        correct, result, error = parser(result)
        if not correct:
            print("Incorrect input, try again")
            print("Tip:", error)
    return result


def configuration_prompt():
    config = {}
    print("Configuration:")
    config['debug'] = simple_prompt("Show debug info(yes = On / yes = Off): ", Parser.boolean)
    config["role"] = simple_prompt("Role (authenticator | peer):", Parser.role)
    config['local_name'] = simple_prompt("Local name (min 1char):", Parser.min_len)
    if config['role'] == 'authenticator':
        config['port'] = simple_prompt("Port:", Parser.positive_int)
        config['peer_limit'] = simple_prompt("Peer limit(should be 255 or lower):", Parser.positive_int)
    elif config['role'] == 'peer':
        config['authenticator'] = simple_prompt("Authenticators address:", Parser.IP)
        config['port'] = simple_prompt("Port:", Parser.positive_int)
        config['identity'] = simple_prompt("Identity:", Parser.min_len)
        config['secret'] = simple_prompt("Secret:", Parser.min_len)
    config['chunk_size'] = simple_prompt("Chunk size:", Parser.positive_int)
    return config


def configure():
    config = configuration_prompt()
    if config['role'] == 'authenticator':
        try:
            config['socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            config['socket'].bind(('', config['port']))
            config['socket'].listen(config['peer_limit'])
        except socket.error:
            log(config['debug'], "Failed to set up the authenticator to listen on port {}".format(config['port']))
            sys.exit(1)
    return config


class Code(Enum):
    request = 0x00
    challenge = 0x01
    response = 0x02
    success = 0x03
    failure = 0x04


# Send/Receive

def send_packet(config, session, msg):
    sent = 0
    log(config['debug'],
        "Starting to send msg to {} with chunks of {} octets".format(session['addr'], config['chunk_size']))
    while sent < len(msg) and not session['conn']._closed:
        time.sleep(random.randint(0, 100) / 200)
        try:
            just_sent = session['conn'].send(msg[sent:sent + config['chunk_size']])
        except (socket.error, OSError):
            log(config['debug'], "Connection with {} lost.".format(session['addr']))
            session['conn'].close()
            return False
        if just_sent == 0:
            log(config['debug'], "Connection with {} lost.".format(session['addr']))
            session['conn'].close()
            return False
        sent += just_sent
    return not session['conn']._closed


def receive_pakcet(config, session, ptype=None):
    isComplete = False
    msg_len = 4
    gotLen = False
    gotCode = True if not ptype else False
    msg = b''
    log(config['debug'], "Receiving packet from [{}]".format(session['addr']))
    while not isComplete and not session['conn']._closed:
        chunk = session['conn'].recv(msg_len)
        if not chunk:
            log(config['debug'], "Connection with {} lost".format(session['addr']))
            session['conn'].close()
        msg += chunk
        if len(msg) >= 1 and not gotCode:
            if msg[0] is not ptype.value:
                log(config['debug'],
                    "Message from {} was not a {} as expected. Connection shutdown.".format(session['addr'],
                                                                                            ptype.name))
                session['conn'].close()
            gotCode = True
        if len(msg) >= msg_len and not gotLen:
            msg_len = int.from_bytes(msg[2:4], byteorder="big", signed=False)
            gotLen = True
        elif len(msg) == msg_len:
            return {'mode': msg[0], 'id': msg[1], 'len': msg_len, 'data': msg[4:]}
        elif len(msg) > msg_len:
            log(config['debug'],
                "Unexpectedly long packet received from {}. Connection shutdown.".format(session['addr']))
            session['conn'].close()


# Peer

def send_request(config, session):
    data = config['identity'].encode()
    length = (len(data) + 4).to_bytes(2, byteorder='big')
    complete = send_packet(config, session, Code.request.value.to_bytes(1, byteorder='big') + b'\x00' + length + data)
    if not complete:
        raise InterruptedError()


def receive_challenge(config, session):
    packet = receive_pakcet(config, session, Code.challenge)
    if not packet:
        raise InterruptedError()
    session['id'] = packet['id'].to_bytes(1, byteorder='big')
    session['chal'] = packet['data'][1:1 + packet['data'][0]]
    log(config['debug'], "Challenge received: {}".format(format_octet(session['chal'])))
    session['auth_name'] = packet['data'][1 + packet['data'][0]:].decode()
    log(config['debug'], "Authenticator\'s name: {}".format(session['auth_name']))


def send_response(config, session):
    response = sha256(session['id'] + config['secret'].encode() + session['chal']).digest()
    log(config['debug'], "Responded: {}".format(format_octet(response)))
    data = len(response).to_bytes(1, byteorder='big') + response + config['local_name'].encode()
    length = (len(data) + 4).to_bytes(2, byteorder='big')
    complete = send_packet(config, session,
                           Code.response.value.to_bytes(1, byteorder='big') + session['id'] + length + data)
    if not complete:
        raise InterruptedError()


def receive_result(config, session):
    packet = receive_pakcet(config, session)
    if not packet:
        raise InterruptedError()
    if packet['mode'] == Code.success.value:
        log(config['debug'], "Authentication successful!")
        return True
    elif packet['mode'] == Code.failure.value:
        log(config['debug'], "Authentication Failed! Message: {}".format(packet['data'].decode()))
        return False
    else:
        raise InterruptedError()


def handle_peer(config):
    session = {'conn': socket.socket(socket.AF_INET, socket.SOCK_STREAM),
               'addr': config['authenticator'] + ":" + str(config['port'])}
    try:
        session['conn'].connect((config['authenticator'], config['port']))
        log(config['debug'], "Connected to {}".format(session['addr']))
    except socket.error:
        log(config['debug'], "Could not connect to the authenticator at {}".format(session['addr']))
    try:
        send_request(config, session)
        receive_challenge(config, session)
        send_response(config, session)
        receive_result(config, session)
    except InterruptedError:
        pass
    except:
        print("Unexpected error:", sys.exc_info())
        raise
    finally:
        if not session['conn']._closed:
            session['conn'].close()


# Authenticator

def receive_request(config, session):
    packet = receive_pakcet(config, session, Code.request)
    if not packet:
        raise InterruptedError()
    else:
        if packet['id'] != 0:
            log(config['debug'], "Request with non 0 id field received from {}".format(session['addr']))
            raise InterruptedError()
        session['identity'] = codecs.decode(packet['data'])
        log(config['debug'],
            "Peer {} trying to authenticate with identity: {}".format(session['addr'], session['identity']))


def send_challenge(config, session):
    session['id'] = IDGen.next()
    log(config['debug'], 'ID {} asigned to {}\'s authentication'.format(session['id'][0], session['addr']))
    session['chal'] = gen_challenge()
    log(config['debug'],
        'Challenge for {}\'s authentication is {}'.format(session['addr'], format_octet(session['chal'])))
    data = len(session['chal']).to_bytes(1, byteorder="big", signed=False) + session['chal'] + config[
        'local_name'].encode()
    length = (len(data) + 4).to_bytes(2, byteorder='big', signed=False)
    completed = send_packet(config, session,
                            Code.challenge.value.to_bytes(1, byteorder='big') + session['id'] + length + data)
    if not completed:
        raise InterruptedError()
    log(config['debug'], "Challenge sent to {}".format(session['addr']))


def receive_response(config, session):
    packet = receive_pakcet(config, session, Code.response)
    if not packet:
        raise InterruptedError()
    if packet['id'] != session['id'][0]:
        log(config['debug'],
            "Response from {} contains different id. Expected: {} Got: {}".format(session['addr'], session['id'][0],
                                                                                  packet['id']))
        raise InterruptedError()
    if packet['data'][0] >= len(packet['data']):
        log(config['debug'], "Response from {} has an unexpected value length".format(session['addr']))
        raise InterruptedError()
    session['response'] = packet['data'][1:1 + packet['data'][0]]
    log(config['debug'], "Response received: {}".format(format_octet(session['response'])))
    session['remote_name'] = packet['data'][1 + packet['data'][0]:]
    log(config['debug'], "Remote\'s name: {}".format(session['remote_name'].decode()))


def send_result(config, session):
    result = Code.failure
    secret = None
    try:
        secret = users[session['identity']]
    except KeyError:
        pass
    if secret:
        local = sha256(session['id'] + secret.encode() + session['chal']).digest()
        log(config['debug'], "Locally generated response value (expected one): {}".format(format_octet(local)))
        if local == session['response']:
            result = Code.success
    else:
        log(config['debug'],
            "{} tried to authenticate with a non existent identity: {}".format(session['addr'], session['identity']))
    if result == Code.failure:
        data = "Authentication failure".encode()
    else:
        data = "Authentication successful".encode()
    length = (len(data) + 4).to_bytes(2, byteorder='big', signed=False)
    correct = send_packet(config, session, result.value.to_bytes(1, byteorder='big') + session['id'] + length + data)
    if not correct:
        raise InterruptedError()
    log(config['debug'],
        "Authentication resulted on {} for identity {} on {} from {}".format(result.name, session['identity'],
                                                                             session['remote_name'].decode(),
                                                                             session['addr']))
    return True if result == Code.success else False


def handle_connection(conn, addr, config):
    session = {'conn': conn, 'addr': addr}
    try:
        log(config['debug'], "The peer {} connected".format(addr))
        with conn:
            receive_request(config, session)
            send_challenge(config, session)
            receive_response(config, session)
            send_result(config, session)
        log(config['debug'], "Peer {} disconnected".format(addr))
    except InterruptedError:
        pass
    except:
        print("Unexpected error:", sys.exc_info())
        raise
    finally:
        if not session['conn']._closed:
            session['conn'].close()


def handle_authenticator(config):
    executor = ThreadPoolExecutor(config['peer_limit'])
    print_users()
    print("Acepting authentication requests..."
          " Press ctrl+c to close")
    try:
        while True:
            conn, addr = config['socket'].accept()
            executor.submit(handle_connection, conn, addr, config)
    except KeyboardInterrupt:
        config['socket'].close()
        executor.shutdown(True)
        raise
    finally:
        config['socket'].close()


# main

if __name__ == '__main__':
    try:
        conf = configure()
        if conf['role'] == 'authenticator':
            handle_authenticator(conf)
        elif conf['role'] == 'peer':
            handle_peer(conf)
    except KeyboardInterrupt:
        print("Program interrupted by the user")
