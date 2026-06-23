import sys
import datetime

from cept import Cept

class Util:
    VALIDATE_INPUT_OK = 0
    VALIDATE_INPUT_BAD = 1
    VALIDATE_INPUT_RESTART = 2

    def readchar():
        c = sys.stdin.buffer.read(1)
        if not c:
            sys.stderr.write("client disconnected, shutting down.\n")
            exit(0)
        if c[0] <= 0x7f:
            return chr(c[0])
        else:
            return chr(0)

    def create_system_message(code):
        text = ""
        prefix = "SH"
        if code == 0:
            text = "                               "
        elif code == 10:
            text = "Scrolling back not possible    "
        elif code == 44:
            text = "Send? Yes:19 No:2              "
        elif code == 47:
            text = "Send? Yes:19 No:2"
        elif code == 55:
            text = "Input is being processed       "
        elif code == 100 or code == 101:
            text = "Page not available             "
        elif code == 291:
            text = "Page is being built            "
        # 31 is blog page
        elif code == 31:
            text = "Blog successfully published"
        # 311 is blog publish question 
        elif code == 311:
            text = "Publish? Yes: 19 No: 2"
        elif code == 321:
            text = "Save changes? Yes: 19 No: 2"
        elif code == 32:
            text = "Saved."
    
        msg = bytearray(Cept.service_break(24))
        msg.extend(Cept.clear_line())
        msg.extend(Cept.from_str(text, 1))
        msg.extend(Cept.hide_text())
        msg.extend(b'\b')
        msg.extend(Cept.from_str(prefix))
        msg.extend(Cept.from_str(str(code)).rjust(3, b'0'))
        msg.extend(Cept.service_break_back())
        return msg
    
    def create_custom_system_message(text):
        msg = bytearray(Cept.service_break(24))
        msg.extend(Cept.clear_line())
        msg.extend(Cept.from_str(text, 1))
        msg.extend(Cept.service_break_back())
        return msg

    def wait_for_ter():
        # TODO: use an editor for this, too!
        sys.stdout.buffer.write(Cept.sequence_end_of_page())
        sys.stdout.flush()
        while True:
            c = Util.readchar()
            if ord(c) == Cept.ter():
                sys.stdout.write(c)
                sys.stdout.flush()
                break
        cept_data = bytearray(Util.create_system_message(0))
        cept_data.extend(Cept.sequence_end_of_page())
        sys.stdout.buffer.write(cept_data)
        sys.stdout.flush()
