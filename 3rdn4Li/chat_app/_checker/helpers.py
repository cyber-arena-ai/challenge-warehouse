import requests
import string
import secrets
import logging

def randomUser():
    username = ''.join([secrets.choice(string.ascii_letters) for _ in range(64)])
    return username

def check_json_key(res, key):
    if res.status_code != 200:
        return False, f"Status code {res.status_code}"
    
    logging.info(res.content)

    try:
        res_json = res.json()
    except Exception as e:
        logging.error("Exception: " + str(e))

    
    if "error" in res_json:
        return False, res_json['error']
    
    logging.info(res.content)
    return True, res.json()[key]

def register(url, username, password):
    logging.info("@ Register user")
    data = {
        "name": username,
        "password": password
    }
    logging.info(f"Register user on {url}/register")
    res = requests.post(url + '/register', json=data)
    return check_json_key(res, "session")

def login(url, username, password):
    logging.info("@ Login user")
    data = {
        "name": username,
        "password": password
    }
    res = requests.post(url + '/login', json=data)
    return check_json_key(res, "session")




def create_chat(url, session, guest_name):
    logging.info(f"@ Create Chat")
    data = {
        "guest": guest_name
    }
    headers = {
        "X-Auth-Token": session
    }

    logging.info(f"Data: {data}")
    logging.info(f"Headers: {headers}")

    res = requests.post(url + '/chat', headers=headers, json=data)
    logging.info(f"Req: {res.request.headers}")
    return check_json_key(res, "data")

def post_message(url, session, chat_id, message):
    logging.info("@ Post Message")
    data = {
        "chat_id": chat_id,
        "message": message
    }
    headers = {
        "X-Auth-Token": session
    }
    res = requests.post(url + '/message', headers=headers, json=data)
    return check_json_key(res, "data")
    
def get_messages(url, session, chat_id):
    logging.info("@ Get Message")
    data = {
        "chat_id": chat_id
    }
    headers = {
        "X-Auth-Token": session
    }
    res = requests.post(url + '/chat_messages', headers=headers, json=data)
    return check_json_key(res, "data")

def get_chats(url, session):
    logging.info("@ Get Chats")
    headers = {
        "X-Auth-Token": session
    }
    # logging.info(f"meHeaders: {headers}")
    res = requests.get(url + '/me', headers=headers)
    logging.info(f"meReq: {res.request.headers}")
    return check_json_key(res, "data")

if __name__ == '__main__':
    pass
    # session = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiQmVubnkifQ.kEJi7cSErTkeo420tPazWCet62gAa9krMIbznyAlqOc'
    #create_chat(session, 'tim')
    #post_message(session, 1, 'Hello World!')
