import sys
import datetime

from cept import Cept
from user import User
from util import Util

class Login_UI:
	def btx_logo():
		return Cept.from_aa(
			[
				"                                                       ",
				"               xxxxxxxxxxxxxxxxxxxxxxxxx               ",
				"           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx           ",
				"         xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx         ",
				"       xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx       ",
				"      xxxxxxxxxxxxxx               xxxxxxxxxxxxxx      ",
				"      xxxxxxxxxxxxx                 xxxxxxxxxxxxx      ",
				"      xxxxxxxxxxxxx                 xxxxxxxxxxxxx      ",
				"      xxxxxxxxxxxx                   xxxxxxxxxxxx      ",
				"       xxxxxxxxx                       xxxxxxxxx       ",
				" x      xxxxx                             xxxxx      x ",
				"  xx                                               xx  ",
				"   xxx                                           xxx   ",
				"    xxxx                                       xxxx    ",
				"     xxxxx                                   xxxxx     ",
				"      xxxxxx                               xxxxxx      ",
				"       xxxxxx                             xxxxxx       ",
				"        xxxxxxxx  xxxxxxxxxxxxxxxxxxxx  xxxxxxx        ",
				"         xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx         ",
				"          xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx          ",
				"           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx           ",
				"           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx           ",
				"           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx           ",
				"           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx           ",
				"           xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx           ",
				"           xxxx xxxxxxxxxxxxxxxxxxxxxxx xxxx           ",
				"           xxxxx xxxxxxxxxxxxxxxxxxxxx xxxxx           ",
				"           xxxxx  xxxxxxxxxxxxxxxxxxx  xxxxx           ",
				"           xxxxxx  xxxxxxxxxxxxxxxxx  xxxxxx           ",
				"           xxxxxx   xxxxxxxxxxxxxxx   xxxxxx           ",
				"            xxxxxx   xxxxxxxxxxxxx   xxxxxx            ",
				"            xxxxxxxx  xxxxxxxxxxx  xxxxxxxx            ",
				"            xxxxxxxxx  xxxxxxxxx  xxxxxxxxx            ",
				"            xxxxxxxxxxx xxxxxxx xxxxxxxxxxx            ",
				"            xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx            ",
				"            xxxxxxxxxxxxxx   xxxxxxxxxxxxxx            ",
				"            xxxxxxxxxxxxxx   xxxxxxxxxxxxxx            ",
				"              xxxxxxxxxxxx   xxxxxxxxxxxx              ",
				"                 xxxxxxxxxx xxxxxxxxxx                 ",
				"                    xxxxxxx xxxxxxx                    ",
				"                       xxxx xxxx                       ",
				"                          xxx                          ",
				"                                                       ",
			], 6
		)

	def callback_login(cls, input_data, dummy):
		if not User.login(input_data["user_id"], input_data["ext"], input_data["password"]):
			sys.stderr.write("login incorrect\n")
			msg = Util.create_custom_system_message("Invalid participant/password -> #")
			sys.stdout.buffer.write(msg)
			sys.stdout.flush()
			Util.wait_for_ter()
			return Util.VALIDATE_INPUT_RESTART
		else:
			sys.stderr.write("login ok\n")
			return Util.VALIDATE_INPUT_OK

	def create_login():
		meta = {
			"clear_screen": False,
			"links": {
			},
			"publisher_color": 7,
			"inputs": {
				"fields": [
					{
						"name": "user_id",
						"hint": "Enter participant no. or #",
						"line": 18,
						"column": 26,
						"height": 1,
						"width": 30,
						"bgcolor": 12,
						"fgcolor": 3
					},
					{
						"name": "ext",
						"hint": "Enter extension or #",
						"line": 20,
						"column": 27,
						"height": 1,
						"width": 1,
						"bgcolor": 12,
						"fgcolor": 3,
						"type": "number",
						"cursor_home": True,
						"default": "1"
					},
					{
						"name": "password",
						"hint": "Next field: #; leave empty for guest",
						"line": 22,
						"column": 26,
						"height": 1,
						"width": 14,
						"bgcolor": 12,
						"fgcolor": 3,
						"type": "password",
						"validate": "call:Login_UI.callback_login"
					}
				],
				"confirm": False,
				"target": "page:000001a",
				"no_navigation": True
			}
		}

		data_cept = bytearray()
		data_cept.extend(Cept.parallel_mode())
		data_cept.extend(Cept.clear_screen())
		data_cept.extend(Cept.set_cursor(2, 1))
		data_cept.extend(Cept.set_screen_bg_color(12))
		data_cept.extend(Cept.set_fg_color(7))
		data_cept.extend(Login_UI.btx_logo())
		data_cept.extend(Cept.set_left_g3())
		data_cept.extend(Cept.set_fg_color(15))
		data_cept.extend(Cept.repeat("Q", 40))
		data_cept.extend(Cept.set_fg_color(7))
		data_cept.extend(Cept.set_left_g0())
		data_cept.extend(Cept.set_cursor(18, 8))
		data_cept.extend(Cept.from_str("Participant:"))
		data_cept.extend(Cept.set_cursor(20, 8))
		data_cept.extend(Cept.from_str("Extension:"))
		data_cept.extend(Cept.set_fg_color(3))
		data_cept.extend(Cept.set_cursor(20, 26))
		data_cept.extend(b'-')
		data_cept.extend(Cept.set_fg_color(7))
		data_cept.extend(Cept.set_cursor(22, 8))
		data_cept.extend(Cept.from_str("Pers. password:"))
		data_cept.extend(b'\r\n')
		data_cept.extend(Cept.set_left_g3())
		data_cept.extend(Cept.set_fg_color(15))
		data_cept.extend(Cept.repeat("Q", 40))
		return (meta, data_cept)

	def create_logout():
		meta = {
			"clear_screen": False,
			"links": {
				"#": "00000"
			},
			"publisher_color": 7
		}

		data_cept = bytearray()
		data_cept.extend(Cept.parallel_mode())
		data_cept.extend(Cept.clear_screen())
		data_cept.extend(Cept.set_cursor(2, 1))
		data_cept.extend(Cept.set_screen_bg_color(12))
		data_cept.extend(Cept.set_fg_color(7))
		data_cept.extend(Login_UI.btx_logo())
		data_cept.extend(Cept.set_left_g3())
		data_cept.extend(Cept.set_fg_color(15))
		data_cept.extend(Cept.repeat("Q", 40))
		data_cept.extend(Cept.set_fg_color(7))
		data_cept.extend(Cept.set_left_g0())
		data_cept.extend(Cept.set_cursor(19, 10))
		data_cept.extend(Cept.from_str("Thank you for calling!"))
		data_cept.extend(b'\r\n')
		data_cept.extend(b'\r\n')
		data_cept.extend(Cept.set_left_g3())
		data_cept.extend(Cept.set_fg_color(15))
		data_cept.extend(Cept.repeat("Q", 40))
		return (meta, data_cept)

	def notifications(user):
		if user.user_id == "0":
			return (
				"You have signed in as guest user.\n"
				"To set up your own account, allowing\n"
				"you to send and receive messages,\n"
				"press 7."
			)
		else:
			return ""

	def create_start(user):
		links = { "#": "0" }

		if user.user_id == "0":
			links["7"] = "77"

		meta = {
			"include": "a",
			"clear_screen": True,
			"links": links,
			"publisher_color": 7
		}

		t = datetime.datetime.now()
		current_date = t.strftime("%d.%m.%Y  %H:%M")
		if user.stats.last_login is not None:
			t = datetime.datetime.fromtimestamp(user.stats.last_login)
			last_date = t.strftime("%d.%m.%Y")
			last_time = t.strftime("%H:%M")
		else:
			last_date = "--.--.----"
			last_time = "--:--"

		user_name = ""
		if user.salutation:
			user_name += user.salutation + "\n"
		if user.first_name:
			user_name += user.first_name + "\n"
		if user.last_name:
			user_name += user.last_name + "\n"

		notifications = Login_UI.notifications(user)

		data_cept = bytearray()
		data_cept.extend(Cept.clear_screen())
		data_cept.extend(Cept.cursor_home())
		data_cept.extend(b'\n')
		data_cept.extend(Cept.set_palette(1))
		data_cept.extend(Cept.set_screen_bg_color_simple(4))
		data_cept.extend(Cept.load_g0_g0())
		data_cept.extend(Cept.set_left_g0())
		data_cept.extend(Cept.parallel_mode())
		data_cept.extend(Cept.set_palette(0))
		data_cept.extend(Cept.code_9e())
		data_cept.extend(Cept.set_fg_color_simple(7))
		data_cept.extend(Cept.load_g0_drcs())
		data_cept.extend(Cept.set_left_g0())
		data_cept.extend(b'!"#\r\n$%&')
		data_cept.extend(Cept.cursor_up())
		data_cept.extend(Cept.cursor_right())
		data_cept.extend(Cept.load_g0_g0())
		data_cept.extend(Cept.set_left_g0())
		data_cept.extend(b'\n')
		data_cept.extend(Cept.double_height())
		data_cept.extend(Cept.from_str("Bildschirmtext"))
		data_cept.extend(b'\r\n')
		data_cept.extend(Cept.set_line_bg_color_simple(4))
		data_cept.extend(b'\n')
		data_cept.extend(Cept.set_line_bg_color_simple(4))
		data_cept.extend(Cept.set_palette(1))
		data_cept.extend(Cept.double_height())
		data_cept.extend(b'\r')
		data_cept.extend(Cept.from_str("German Federal Postal Service"))
		data_cept.extend(b'\n\r')
		data_cept.extend(Cept.set_palette(0))
		data_cept.extend(Cept.normal_size())
		data_cept.extend(Cept.code_9e())
		data_cept.extend(b'\r\n')
		data_cept.extend(Cept.set_fg_color_simple(3))
		data_cept.extend(Cept.from_str(current_date))
		data_cept.extend(Cept.set_fg_color_simple(7))
		data_cept.extend(b'\r\n\n')
		data_cept.extend(Cept.from_str("Hello"))
		data_cept.extend(b'\r\n')
		data_cept.extend(Cept.from_str(user_name))
		data_cept.extend(b'\r\n')
		data_cept.extend(Cept.set_fg_color_simple(3))
		data_cept.extend(Cept.from_str(notifications))
		data_cept.extend(Cept.set_fg_color_simple(7))
		data_cept.extend(Cept.set_cursor(19, 1))
		data_cept.extend(Cept.from_str("You last used Bildschirmtext"))
		data_cept.extend(b'\r\n')
		data_cept.extend(Cept.from_str("on "))
		data_cept.extend(Cept.set_fg_color_simple(3))
		data_cept.extend(Cept.from_str(last_date))
		data_cept.extend(Cept.set_fg_color_simple(7))
		data_cept.extend(Cept.from_str(" until "))
		data_cept.extend(Cept.set_fg_color_simple(3))
		data_cept.extend(Cept.from_str(last_time))
		data_cept.extend(Cept.set_fg_color_simple(7))
		data_cept.extend(b'\r\n\r\n\r\n')
		data_cept.extend(Cept.set_line_bg_color_simple(4))
		data_cept.extend(Cept.from_str("Continue with #  or  *page no.#"))
		return (meta, data_cept)

	def create_page(user, pagenumber):
		if pagenumber == "00000a":
			return Login_UI.create_login()
		elif pagenumber == "000001a":
			return Login_UI.create_start(user)
		elif pagenumber == "9a":
			return Login_UI.create_logout()
		else:
			return None
