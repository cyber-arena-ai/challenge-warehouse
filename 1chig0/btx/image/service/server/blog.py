import sys
import os
import re
import json
import time
import datetime

from cept import Cept
from user import User
from util import Util

PATH_BLOGS = "../blogs/"

class Blog:
    d = None
    index = None
    owner_user_id = None

    def __init__(self, d, index, owner_user_id):
        self.d = d
        self.index = index
        self.owner_user_id = owner_user_id

    def from_date(self):
        t = datetime.datetime.fromtimestamp(self.d["timestamp"])
        return t.strftime("%d.%m.%Y")

    def from_time(self):
        t = datetime.datetime.fromtimestamp(self.d["timestamp"])
        return t.strftime("%H:%M")

    def content(self):
        return self.d["content"]

    def title(self):
        return self.d["title"]

    def visibility(self):
        return self.d["visibility"]

    def notes(self):
        return self.d["notes"]


class Blogging:
    user = None
    d = None
    current_index = 0

    def __init__(self, u):
        self.user = u

    def dict_filename(user_id, ext):
        return PATH_BLOGS + user_id + "-" + ext + ".blog"

    def load_dict(user_id, ext):
        filename = Blogging.dict_filename(user_id, ext)
        if not os.path.isfile(filename):
            d = {"blogs": []}
        else:
            with open(filename) as f:
                d = json.load(f)
        return d

    def save_dict(user_id, ext, d):
        with open(Blogging.dict_filename(user_id, ext), 'w') as f:
            json.dump(d, f)

    def load(self):
        self.d = Blogging.load_dict(self.user.user_id, self.user.ext)

    def save(self):
        Blogging.save_dict(self.user.user_id, self.user.ext, self.d)

    def select(self, start, count):
        self.load()
        return [Blog(x,index+start, self.user.user_id) for index,x in enumerate(self.d["blogs"][start:min(start+count,len(self.d["blogs"]))])]

    def num_blogs(self):
        return len(self.d["blogs"])

    def publish(self, title, content, visibility, notes):
        d = Blogging.load_dict(self.user.user_id, self.user.ext)
        d["blogs"].append(
            {
                "title": title ,
                "personal_data": False,
                "timestamp": time.time(),
                "content": content,
                "visibility": visibility,
                "notes": notes,
            },
        )
        Blogging.save_dict(self.user.user_id, self.user.ext, d)

    def needs_update(self, title, content, visibility):
        d = Blogging.load_dict(self.user.user_id, self.user.ext)
        for blog in d["blogs"]:
            if blog["title"] == title:
                return blog["content"] != content or blog["visibility"] != visibility
        return False
        
    def update(self, title, content, visibility):
        d = Blogging.load_dict(self.user.user_id, self.user.ext)
        for blog in d["blogs"]:
            if blog["title"] == title:
                blog["content"] = content
                blog["visibility"] = visibility
        Blogging.save_dict(self.user.user_id, self.user.ext, d)
        


class Blog_UI:

    # private
    def blog_create_title(title):
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

    # private
    def blog_create_menu(title, items):
        data_cept = bytearray(Blog_UI.blog_create_title(title))
        data_cept.extend(b"\n\r\n\r")
        i = 1
        for item in items:
            data_cept.extend(
                Cept.from_str(
                    str(i)) +
                b'  ' +
                Cept.from_str(item))
            data_cept.extend(b"\r\n\r\n")
            i += 1

        data_cept.extend(b'\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n')
        data_cept.extend(Cept.set_line_bg_color_simple(4))
        data_cept.extend(b'0\x19\x2b')
        data_cept.extend(Cept.from_str(" Overview"))

        return data_cept

    def blog_create_main_menu():
        meta = {
            "publisher_name": "!BTX",
            "include": "a",
            "clear_screen": True,
            "links": {
                "0": "0",
                "1": "31",
                "2": "32",
                "3": "33"
            },
            "publisher_color": 7
        }

        data_cept = Blog_UI.blog_create_menu(
            "Blog Service",
            [
                "New",
                "Edit",
                "List"
            ]
        )
        return (meta, data_cept)

    def blog_create_list(user):
        meta = {
            "publisher_name": "!BTX",
            "include": "a",
            "clear_screen": True,
            "publisher_color": 7,
        }

        links = {
            "0": "3"
        }
        inp = ""
        while True:
            c = Util.readchar()
            if ord(c) != Cept.ter():
                inp += c
                sys.stdout.write(c)
                sys.stdout.flush()
            if ord(c) == Cept.ter():
                break
        target_user = User.get(inp,"1")
        data_cept = bytearray(Blog_UI.blog_create_title(f"Blogs of {target_user.salutation} {target_user.last_name}"))
        blogs = target_user.blogging.select(0, 9)
        if len(blogs) == 0:
            links["^"] = f"error:Blog_UI.blog_error_handler:{inp}"
            meta["autoplay"] = True
        else:
            for index in range(0, len(blogs)):
                if index < len(blogs):
                    blog = blogs[index]
                    if blog.d["visibility"] != "true" and (not (user.user_id == blog.owner_user_id)):
                        continue
                    data_cept.extend(Cept.from_str(str(index + 1)) + b'  ')
                    data_cept.extend(Cept.from_str(blog.title()))
                    data_cept.extend(b'\r\n\r\n')
                    links[str(index + 1)] = ""
                    links[str(index + 1)]+= "34"
                    links[str(index + 1)]+= str(index + 1)
                    links[str(index + 1)]+= target_user.user_id


        meta["links"] = links
        return (meta, data_cept)

    def callback_validate_title(cls, input_data, dummy):
        pass

    def callback_validate_content(cls, input_data, dummy):
        pass

    def blog_view(blog_id, user_id):
        user = User.get(user_id, "1")
        current_blog = user.blogging.select(blog_id, 1)[0]
        meta = {"include": "a",
                "publisher_name": "!BTX",
                "clear_screen": True,
                "links": {"0": "3"},
                "publisher_color": 7
                }

        current_date = datetime.datetime.now().strftime("%d.%m.%Y")
        current_time = datetime.datetime.now().strftime("%H:%M")

        data_cept = bytearray(Cept.set_cursor(2, 1))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(Cept.set_screen_bg_color_simple(4))
        data_cept.extend(
            b'\x1b\x28\x40'                                    # load G0 into G0
        )
        data_cept.extend(
            b'\x0f'                                            # G0 into left charset
        )
        data_cept.extend(Cept.parallel_mode())
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.code_9e())
        data_cept.extend(b'\n\r')
        data_cept.extend(b'\n')
        data_cept.extend(Cept.set_line_bg_color_simple(4))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(b'\r')
        data_cept.extend(Cept.from_str("Blogging Service"))
        data_cept.extend(b'\n\r')
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.normal_size())
        data_cept.extend(Cept.code_9e())
        data_cept.extend(Cept.set_fg_color_simple(7))
        data_cept.extend(Cept.set_cursor(7, 1))
        data_cept.extend(Cept.from_str(f"Title: {current_blog.title()}"))
        if User.user().user_id == current_blog.owner_user_id:
            data_cept.extend(Cept.set_cursor(11, 1))
            data_cept.extend(Cept.from_str(f"Notes: {current_blog.notes()}"))
        data_cept.extend(Cept.set_cursor(13, 1))
        data_cept.extend(Cept.from_str("Content:"))
        data_cept.extend(Cept.set_cursor(14, 1))
        data_cept.extend(Cept.from_str(f"{current_blog.content()}"))
        return (meta, data_cept)


    def blog_edit(user):
        current_blog = user.blogging.select(user.blogging.current_index,1)[0]
        user.blogging.current_index = (user.blogging.current_index+1)%user.blogging.num_blogs()
        meta = {"include": "a",
                "clear_screen": True,
                "links": {"0": "3"},
                "publisher_color": 7,
                "inputs": {"fields": [{"name": "title",
                          # "type": "user_id",
                                       "line": 8,
                                       "column": 1,
                                       "height": 1,
                                       "width": 40,
                                       "bgcolor": 4,
                                       "fgcolor": 3,
                                       "default": current_blog.title(),
                                       "validate": "call:Blog_UI.callback_validate_title"},
                                      {"name": "visibility",
                                       "line": 12,
                                       "column": 1,
                                       "height": 1,
                                       "width": 40,
                                       "bgcolor": 4,
                                       "fgcolor": 3,
                                       "default": current_blog.visibility()},
                                      {"name": "notes",
                                       "line": 14,
                                       "column": 1,
                                       "height": 1,
                                       "width": 40,
                                       "bgcolor": 4,
                                       "fgcolor": 3,
                                       "default": current_blog.notes()},
                                      {"name": "content",
                                       "line": 16,
                                       "column": 1,
                                       "height": 6,
                                       "width": 40,
                                       "bgcolor": 4,
                                       "fgcolor": 3,
                                       "default": current_blog.content(),
                                       "validate": "call:Blog_UI.callback_validate_content"}],
                           "action": "edit_blog",
                           "price": 30,
                           "target": "page:32"}}

        current_date = datetime.datetime.now().strftime("%d.%m.%Y")
        current_time = datetime.datetime.now().strftime("%H:%M")

        data_cept = bytearray(Cept.set_cursor(2, 1))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(Cept.set_screen_bg_color_simple(4))
        data_cept.extend(
            b'\x1b\x28\x40'                                    # load G0 into G0
        )
        data_cept.extend(
            b'\x0f'                                            # G0 into left charset
        )
        data_cept.extend(Cept.parallel_mode())
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.code_9e())
        data_cept.extend(b'\n\r')
        data_cept.extend(b'\n')
        data_cept.extend(Cept.set_line_bg_color_simple(4))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(Cept.double_height())
        data_cept.extend(b'\r')
        data_cept.extend(Cept.from_str("Blogging Service"))
        data_cept.extend(b'\n\r')
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.normal_size())
        data_cept.extend(Cept.code_9e())
        data_cept.extend(Cept.set_fg_color_simple(7))
        data_cept.extend(Cept.set_cursor(7, 1))
        data_cept.extend(Cept.from_str("Title:"))
        data_cept.extend(Cept.set_cursor(11, 1))
        data_cept.extend(Cept.from_str("Public?:"))
        data_cept.extend(Cept.set_cursor(13, 1))
        data_cept.extend(Cept.from_str("Private Notes:"))
        data_cept.extend(Cept.set_cursor(15, 1))
        data_cept.extend(Cept.from_str("Content:"))
        return (meta, data_cept)

    def blog_create_compose(user):
        meta = {"include": "a",
                "clear_screen": True,
                "links": {"0": "3"},
                "publisher_color": 7,
                "inputs": {"fields": [{"name": "title",
                                       "line": 8,
                                       "column": 1,
                                       "height": 1,
                                       "width": 40,
                                       "bgcolor": 4,
                                       "fgcolor": 3,
                                       "validate": "call:Blog_UI.callback_validate_title"},
                                      {"name": "visibility",
                                       "line": 12,
                                       "column": 1,
                                       "height": 1,
                                       "width": 40,
                                       "bgcolor": 4,
                                       "fgcolor": 3,
                                       "default": "true"},
                                      {"name": "notes",
                                       "line": 14,
                                       "column": 1,
                                       "height": 1,
                                       "width": 40,
                                       "bgcolor": 4,
                                       "fgcolor": 3,
                                       "default": ""},
                                      {"name": "content",
                                       "line": 16,
                                       "column": 1,
                                       "height": 6,
                                       "width": 40,
                                       "bgcolor": 4,
                                       "fgcolor": 3,
                                       "validate": "call:Blog_UI.callback_validate_content"}],
                           "action": "publish_blog",
                           "price": 30,
                           "target": "page:3"}}

        current_date = datetime.datetime.now().strftime("%d.%m.%Y")
        current_time = datetime.datetime.now().strftime("%H:%M")

        data_cept = bytearray(Cept.set_cursor(2, 1))
        data_cept.extend(Cept.set_palette(1))
        data_cept.extend(Cept.set_screen_bg_color_simple(4))
        data_cept.extend(
            b'\x1b\x28\x40'                                    # load G0 into G0
        )
        data_cept.extend(
            b'\x0f'                                            # G0 into left charset
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
        data_cept.extend(Cept.from_str("Blogging Service"))
        data_cept.extend(b'\n\r')
        data_cept.extend(Cept.set_palette(0))
        data_cept.extend(Cept.normal_size())
        data_cept.extend(Cept.code_9e())
        data_cept.extend(Cept.set_fg_color_simple(7))
        data_cept.extend(Cept.set_cursor(7, 1))
        data_cept.extend(Cept.from_str("Title:"))
        data_cept.extend(Cept.set_cursor(11, 1))
        data_cept.extend(Cept.from_str("Public?:"))
        data_cept.extend(Cept.set_cursor(13, 1))
        data_cept.extend(Cept.from_str("Private Notes:"))
        data_cept.extend(Cept.set_cursor(15, 1))
        data_cept.extend(Cept.from_str("Content:"))

        return (meta, data_cept)

    def handle_selection(user):
        cept_data = bytearray(Util.create_custom_system_message("Enter user id:"))
        cept_data.extend(Cept.set_cursor(24, 1))
        cept_data.extend(Cept.sequence_end_of_page())
        sys.stdout.buffer.write(cept_data)
        sys.stdout.flush()
        return Blog_UI.blog_create_list(user)

    def blog_error_handler(cls, arg1, arg2):
        return ("39", arg2)

    def blog_error(msg):
        meta = {
            "publisher_name": "!BTX",
            "include": "a",
            "clear_screen": True,
            "publisher_color": 7,
            "links": {
                "0": "3"
            }
        }
        data_cept = bytearray(Blog_UI.blog_create_title(f"Blog Error"))
        data_cept.extend(b'Invalid user ID:\r\n\r\n')
        data_cept.extend(msg.encode())
        return (meta, data_cept)


    def create_page(user, pagenumber, pagearg = None):
        if pagenumber == "3a":
            return Blog_UI.blog_create_main_menu()
        elif pagenumber == "31a":
            return Blog_UI.blog_create_compose(user)
        elif pagenumber == "32a":
            return Blog_UI.blog_edit(user)
        elif pagenumber == "33a":
            return Blog_UI.handle_selection(user)
        elif pagenumber.startswith("34"):
            blog_id = int(pagenumber[2])-1
            user_id = pagenumber[3:-1]
            return Blog_UI.blog_view(blog_id,user_id)
        elif pagenumber.startswith("39"):
            return Blog_UI.blog_error(pagearg)
        else:
            return None
