#!/usr/bin/env python3

import redis

from flask import Flask, render_template, abort, request, make_response
app = Flask(__name__)

import random
import uuid
import json

redis_connection = redis.StrictRedis(host='localhost', port=6379, db=0)
available_ports = range(8001, 8001+100)

def get_previous_results_for_ip(ip):
    if ip is None:
        raise Exception("ip cannot be None")
    results = redis_connection.get("ip_{}".format(ip))
    if results is None:
        results = []
    else:
        results = json.loads(results.decode('utf-8'))

    return results

def get_previous_results_for_id(http2_id):
    if http2_id is None:
        raise Exception("http2_id cannot be None")
    data = redis_connection.get("id_{}".format(http2_id))
    result = None
    if data is not None:
        result = json.loads(data.decode('utf-8'))
    return result


def store_new_connection(connection_info):
    if connection_info is None:
        raise Exception("Connection info cannot be None")

    ip = connection_info['ip']
    http2_id = connection_info['http2_id']
    
    if ip is None:
        raise Exception("IP cannot be None")
    if http2_id is None:
        raise Exception("HTTP2_id cannot be None")

    results_ip = get_previous_results_for_ip(ip)
    results_ip.append(connection_info)
    
    str_results_ip = json.dumps(results_ip)
    
    redis_connection.set("ip_{}".format(ip), str_results_ip)
    redis_connection.set("id_{}".format(http2_id), json.dumps(connection_info))    

def getcookie():
    return request.cookies.get('http2_id')

def setcookie(response, http2_id):
    return response.set_cookie('http2_id', http2_id)

def compute_url(port):
    return "https://localhost:{}".format(port)

def get_user_results():

    http2_id = getcookie()

    if http2_id is None:
        return None

    user_info = redis_connection.get("id_{}".format(http2_id))
    if user_info is None:
        return None

    user_info = json.loads(user_info.decode("utf-8"))

    if "progress" not in user_info.keys():
        progress = 0
    else:
        progress = min(user_info['progress'], 100)
    
    
    if "classification" not in user_info.keys():
        classification = None
    else:
        classification = user_info['classification']

    return (progress, classification)
    

def get_user_info(create = False):
    
    http2_id = getcookie()

    user_info = None
    
    if http2_id is not None:
        user_info = get_previous_results_for_id(http2_id)
        
        if user_info is None:
            http2_id = None
            

    if http2_id is None and create:
        print("lets create a new user info")

        # new user, let generate a new one and store its entry in table
        http2_id = str(uuid.uuid4())

        ua = request.headers.get('User-Agent')
        ip = request.remote_addr

        used_ports = []
        previous_results = get_previous_results_for_ip(ip)
        if len(previous_results) > 0:
            used_ports.extend([result['retained_port'] for result in previous_results])

        free_ports = set(available_ports) - set(used_ports)
        if len(free_ports) == 0:
            print("ERROR: No more free ports for ip {}".format(ip))
            abort(500)
        retained_port = random.choice(list(free_ports))
        
        user_info = {
            "ua": ua,
            "ip": ip,
            "retained_port": retained_port,
            "http2_id": http2_id
        }
            
        store_new_connection(user_info)


    return user_info


@app.route('/')
def index():

    user_info = get_user_info(create = True)
    
    if 'classification' in user_info.keys() and user_info['classification'] is not None:
        response = make_response(render_template('index.html', url=""))
    else:
        response = make_response(render_template('index.html', url=compute_url(user_info['retained_port'])))

    setcookie(response, user_info['http2_id'])

    return response

@app.route('/results')
def results():
    user_progress, user_results = get_user_results()

    browser = "unknown"
    percent = 0

    if user_results is not None:
        for k, v in user_results['classification']['summary'].items():
            if v > percent:
                browser = k
                percent = v
    
    return json.dumps({"progress": user_progress, "classification": user_results, "browser": {"name": browser, "percent": percent}})

if __name__ == '__main__':
    app.run()
