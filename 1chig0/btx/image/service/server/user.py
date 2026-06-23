import os
import sys
import json
import time
import re
import pprint

from cept import Cept
from util import Util

PATH_USERS = "../users/"
PATH_SECRETS = "../secrets/"
PATH_STATS = "../stats/"

global_user = None

class Stats():
    last_login = None
    user = None

    def __filename(self):
        return PATH_STATS + self.user.user_id + "-" + self.user.ext + ".stats"

    def __init__(self, user):
        self.user = user
        filename = self.__filename()
        if os.path.isfile(filename):
            try:
                with open(filename) as f:
                    stats = json.load(f)
                    self.last_login = stats.get("last_use")
            except:
                self.last_login = { "last_use": time.time() }
    
    def update(self):
        stats = { "last_use": time.time() }
        with open(self.__filename(), 'w') as f:
            json.dump(stats, f)
    

class User():
    user_id = None
    ext = None
    personal_data = False

    salutation = None
    first_name = None
    last_name = None
    org_name = None
    org_add_name = None
    street = None
    zip = None
    city = None
    country = None

    stats = None
    blogging = None

    def user():
        global global_user
        return global_user

    @classmethod
    def sanitize(cls, user_id, ext):
        if user_id is None or user_id == "":
            user_id = "0"
        if ext is None or ext == "":
            ext = "1"
        sane_user_id = ""
        for c in user_id:
            if c.isdigit():
                sane_user_id += c
        return (sane_user_id, ext)

    def user_filename(user_id, ext):
        return PATH_USERS + user_id + "-" + ext + ".user"

    def secrets_filename(user_id, ext):
        return PATH_SECRETS + user_id + "-" + ext + ".secrets"

    @classmethod
    def exists(cls, user_id, ext = "1"):
        (user_id, ext) = cls.sanitize(user_id, ext)
        filename = User.user_filename(user_id, ext)
        return os.path.isfile(filename)
    
    @classmethod
    def get(cls, user_id, ext, personal_data = False):
        (user_id, ext) = cls.sanitize(user_id, ext)
        from blog import Blogging 
        filename = User.user_filename(user_id, ext)
        if not os.path.isfile(filename):
            return None
        with open(filename) as f:
            dict = json.load(f)
    
        user = cls()
        user.user_id = user_id
        user.ext = ext
        user.salutation = dict.get("salutation", "")
        user.first_name = dict.get("first_name", "")
        user.last_name = dict.get("last_name", "")
        user.org_name = dict.get("org_name", "")
        user.org_add_name = dict.get("org_add_name", "")
        
        user.personal_data = personal_data
        if (personal_data):
            user.street = dict.get("street", "")
            user.zip = dict.get("zip", "")
            user.city = dict.get("city", "")
            user.country = dict.get("country", "")
            user.stats = Stats(user)
        
        user.blogging = Blogging(user)

        return user

    @classmethod
    def create(cls, user_id, ext, password, salutation, last_name, first_name, street, zip, city, country):
        user_filename = User.user_filename(user_id, ext)
        secrets_filename = User.secrets_filename(user_id, ext)
        if os.path.isfile(user_filename) or os.path.isfile(secrets_filename):
            sys.stderr.write("already exists: " + pprint.pformat(user_filename, secrets_filename) + "\n")
            return False
        user_dict = {
            "salutation": salutation,
            "first_name": first_name,
            "last_name": last_name,
            "street": street,
            "zip": zip,
            "city": city,
            "country": country
        }
        with open(user_filename, 'w') as f:
            json.dump(user_dict, f)
        secrets_dict = {
            "password": password
        }
        with open(secrets_filename, 'w') as f:
            json.dump(secrets_dict, f)
        return True

    @classmethod
    def set_active_user(cls, ext = "1", user_id = "0"):
        global global_user
        global_user = cls.get(user_id, ext, True)
        return True if global_user else False

    @classmethod
    def login(cls, user_id, ext, password, force = False):
        (user_id, ext) = cls.sanitize(user_id, ext)
        filename = User.secrets_filename(user_id, ext)
        if not os.path.isfile(filename):
            return None
        with open(filename) as f:
            dict = json.load(f)

        if password != dict.get("password") and not force:
            return None

        return User.set_active_user(ext, user_id)

class User_UI:
    def line():
        data_cept = bytearray()
        data_cept.extend(Cept.set_left_g3())
        data_cept.extend(Cept.set_fg_color(15))
        data_cept.extend(Cept.repeat("Q", 40))
        data_cept.extend(Cept.set_fg_color(7))
        data_cept.extend(Cept.set_left_g0())
        return data_cept

    def create_title(title):
        data_cept = bytearray(Cept.set_cursor(2, 1))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(Cept.set_screen_bg_color_simple(4))
        data_cept.extend(
            b'\x1b\x28\x40'           # load G0 into G0
            b'\x0f'                   # G0 into left charset
        )
        data_cept.extend(Cept.parallel_mode())
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.code_9e())
        data_cept.extend(b'\n\r')
        data_cept.extend(Cept.set_line_bg_color_simple(4))
        data_cept.extend(b'\n')
        data_cept.extend(Cept.set_line_bg_color_simple(4))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(Cept.double_height())
        data_cept.extend(b'\r')
        data_cept.extend(Cept.from_str(title))
        data_cept.extend(b'\n\r')
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.normal_size())
        data_cept.extend(Cept.code_9e())
        data_cept.extend(Cept.set_fg_color_simple(7))
        return data_cept

    def create_title2(title):
        data_cept = bytearray(Cept.set_cursor(2, 1))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(Cept.set_screen_bg_color_simple(4))
        data_cept.extend(
            b'\x1b\x28\x40'           # load G0 into G0
            b'\x0f'                   # G0 into left charset
        )
        data_cept.extend(Cept.parallel_mode())
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.code_9e())
        data_cept.extend(Cept.set_line_bg_color_simple(4))
        data_cept.extend(b'\n')
        data_cept.extend(Cept.set_line_bg_color_simple(4))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(Cept.double_height())
        data_cept.extend(b'\r')
        data_cept.extend(Cept.from_str(title))
        data_cept.extend(b'\n\r')
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.normal_size())
        data_cept.extend(Cept.code_9e())
        data_cept.extend(Cept.set_fg_color_simple(7))
        return data_cept

    def create_add_user():
        meta = {
            "publisher_name": "!BTX",
            "include": "a",
            "clear_screen": True,
            "links": {
                "0": "0",
                "1": "88",
                "2": "89",
                "5": "810"
            },
            "inputs": {
                "fields": [
                    {
                        "name": "user_id",
                        "hint": "Enter preferred part.no. or #",
                        "line": 6,
                        "column": 19,
                        "height": 1,
                        "width": 30,
                        "bgcolor": 12,
                        "fgcolor": 3,
                        "type": "number",
                        "validate": "call:User_UI.callback_validate_user_id"
                    },
                    {
                        "name": "salutation",
                        "hint": "Enter salutation or #",
                        "line": 8,
                        "column": 13,
                        "height": 1,
                        "width": 20,
                        "bgcolor": 12,
                        "fgcolor": 3
                    },
                    {
                        "name": "last_name",
                        "hint": "Enter last name or #",
                        "line": 9,
                        "column": 12,
                        "height": 1,
                        "width": 20,
                        "bgcolor": 12,
                        "validate": "call:User_UI.callback_validate_last_name",
                        "fgcolor": 3
                    },
                    {
                        "name": "first_name",
                        "hint": "Enter first name or #",
                        "line": 10,
                        "column": 13,
                        "height": 1,
                        "width": 20,
                        "bgcolor": 12,
                        "fgcolor": 3
                    },
                    {
                        "name": "street",
                        "hint": "Enter street or #",
                        "line": 11,
                        "column": 9,
                        "height": 1,
                        "width": 20,
                        "bgcolor": 12,
                        "fgcolor": 3
                    },
                    {
                        "name": "zip",
                        "hint": "Enter postal code or #",
                        "line": 12,
                        "column": 6,
                        "height": 1,
                        "width": 5,
                        "bgcolor": 12,
                        "fgcolor": 3,
                        "type": "number"
                    },
                    {
                        "name": "city",
                        "hint": "Enter city or #",
                        "line": 12,
                        "column": 17,
                        "height": 1,
                        "width": 13,
                        "bgcolor": 12,
                        "fgcolor": 3
                    },
                    {
                        "name": "country",
                        "hint": "Enter country code or #",
                        "line": 12,
                        "column": 37,
                        "height": 1,
                        "width": 2,
                        "bgcolor": 12,
                        "fgcolor": 3,
                        "default": "de",
                        "type": "alpha",
                        "cursor_home": True,
                        "overwrite": True
                    },
                    {
                        "name": "password",
                        "hint": "New password",
                        "line": 15,
                        "column": 11,
                        "height": 1,
                        "width": 14,
                        "bgcolor": 12,
                        "fgcolor": 3,
                        "type": "password",
                        "validate": "call:User_UI.callback_validate_password",
                    },
                ],
                "confirm": False,
                "target": "call:User_UI.callback_add_user",
            },
            "publisher_color": 7
        }
        
        data_cept = bytearray()
        data_cept.extend(User_UI.create_title("Register new user"))
        data_cept.extend(b"\r\n")
        data_cept.extend(Cept.from_str("Participant no.:"))
        data_cept.extend(b"\r\n")
        data_cept.extend(Cept.from_str("Extension:"))
        data_cept.extend(Cept.set_cursor(7, 25))
        data_cept.extend(Cept.from_str("-1"))
        data_cept.extend(b"\r\n")
        data_cept.extend(Cept.from_str("Salutation:"))
        data_cept.extend(b"\r\n")
        data_cept.extend(Cept.from_str("Last name:"))
        data_cept.extend(b"\r\n")
        data_cept.extend(Cept.from_str("First name:"))
        data_cept.extend(b"\r\n")
        data_cept.extend(Cept.from_str("Street:"))
        data_cept.extend(b"\r\n")
        data_cept.extend(Cept.from_str("ZIP:"))
        data_cept.extend(Cept.repeat(" ", 7))
        data_cept.extend(Cept.from_str("City:"))
        data_cept.extend(Cept.set_cursor(12, 31))
        data_cept.extend(Cept.from_str("CC:"))
        data_cept.extend(b"\r\n")
        data_cept.extend(User_UI.line())
        data_cept.extend(b"\r\n")
        data_cept.extend(Cept.from_str("Password: "))
        data_cept.extend(b"\r\n\r\n")
        data_cept.extend(User_UI.line())
        return (meta, data_cept)

    def callback_validate_user_id(cls, input_data, dummy):
        if User.exists(input_data["user_id"]):
            msg = Util.create_custom_system_message("Participant no. already assigned! -> #")
            sys.stdout.buffer.write(msg)
            sys.stdout.flush()
            Util.wait_for_ter()
            return Util.VALIDATE_INPUT_BAD
        else:
            return Util.VALIDATE_INPUT_OK

    def callback_validate_last_name(cls, input_data, dummy):
        if not input_data["last_name"]:
            msg = Util.create_custom_system_message("Last name must not be empty! -> #")
            sys.stdout.buffer.write(msg)
            sys.stdout.flush()
            Util.wait_for_ter()
            return Util.VALIDATE_INPUT_BAD
        else:
            return Util.VALIDATE_INPUT_OK

    def callback_validate_password(cls, input_data, dummy):
        if len(input_data["password"]) < 4:
            msg = Util.create_custom_system_message("Password must be >= 4 characters! -> #")
            sys.stdout.buffer.write(msg)
            sys.stdout.flush()
            Util.wait_for_ter()
            return Util.VALIDATE_INPUT_BAD
        else:
            return Util.VALIDATE_INPUT_OK

    def callback_add_user(cls, input_data, dummy):
        if User.create(
            input_data["user_id"],
            "1",
            input_data["password"],
            input_data["salutation"],
            input_data["last_name"],
            input_data["first_name"],
            input_data["street"],
            input_data["zip"],
            input_data["city"],
            input_data["country"]
        ):
            msg = Util.create_custom_system_message("User created. Please sign in. -> #")
            sys.stdout.buffer.write(msg)
            sys.stdout.flush()
            Util.wait_for_ter()
            return "00000"
        else:
            msg = Util.create_custom_system_message("User could not be created. -> #")
            sys.stdout.buffer.write(msg)
            sys.stdout.flush()
            Util.wait_for_ter()
            return "77"

    def create_page(user, pagenumber):
        if pagenumber == "77a":
            return User_UI.create_add_user()
        else:
            return None














