import random
import os
import base64
import string
import wonderwords
import requests
from stegano import lsb
import numpy
from PIL import Image, ImageDraw, ImageFont
import logging
import io
import re

CUR_DIR = "/tmp/"#os.path.dirname(os.path.realpath(__file__))

def generate_name():
  return ''.join(random.choices(string.ascii_letters, k=random.randint(1,31)))

def generate_password():
  return ''.join(random.choices(string.printable, k=random.randint(1,31)))

def generate_comment():
  r = wonderwords.RandomWord()
  return " ".join(r.random_words(32))[0:254]

def update_password(self, session, old_password):
  new_password = generate_password()
  resp = session.post(f"http://{self.ip}:3000"+"/updateProfile/password",data={"password": new_password, "old_password": old_password})
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Used Password: {old_password}\n- New Password: {new_password}\n- Resp Text: {resp.text}")
  return new_password

def update_username(self, session, old_password):
  new_username = generate_name()
  resp = session.post(f"http://{self.ip}:3000"+"/updateProfile/username",data={"username": new_username, "old_password": old_password})
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Used Password: {old_password}\n- New Username: {new_username}\n- Resp Text: {resp.text}")
  return new_username

def update_profilePicture(self, session, image):
  resp = session.post(f"http://{self.ip}:3000"+"/updateProfile/image",files={"image":image})
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Resp Text: {resp.text}")

def upload_public_image(self, session, image):
  resp = session.post(f"http://{self.ip}:3000"+"/upload",data={"public": "public"},files={"image":image})
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Resp Text: {resp.text}")

def upload_private_image(self, session, image):
  resp = session.post(f"http://{self.ip}:3000"+"/upload",data={"public": "private"},files={"image":image})
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Resp Text: {resp.text}")

def post_comment(self, session, image_num, comment):
  resp = session.post(f"http://{self.ip}:3000/image/{image_num}", data={"comment": comment})
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Comment: {comment}\n- Image url: http://{self.ip}:3000/image/{image_num}\n- Resp Text: {resp.text}")
  return comment

def check_register(self, session, username, password):
  resp = session.post(f"http://{self.ip}:3000/auth/register", data={"username" : username, "password": password})
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Username: {username}\n- Password: {password}\n- User Url: http//{self.ip}:3000/view/{username}\n- Resp Text: {resp.text}")

def check_login(self, session, username, password):
  resp = session.post(f"http://{self.ip}:3000/auth/login", data={"username" : username, "password": password})
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Username: {username}\n- Password: {password}\n- User Url: http//{self.ip}:3000/view/{username}\n- Resp Text: {resp.text}")

def create_image_with_flag(flag):
  img_path = create_rand_png()
  flag = lsb.hide(CUR_DIR + f"/images/{img_path}.png", flag)
  flag.save(CUR_DIR + f"/flags/{img_path}.png")
  os.remove(CUR_DIR + f"/images/{img_path}.png")
  flag_bytes = fromPILImageToBytes(Image.open(CUR_DIR +f"/flags/{img_path}.png"))
  os.remove(CUR_DIR + f"/flags/{img_path}.png")
  return flag_bytes

def create_image_with_obv_flag(flag):
  img = Image.fromarray(numpy.ones((300, 300, 3), dtype=numpy.uint8) * 255)
  draw = ImageDraw.Draw(img)

  # Define the text and font
  text = str(flag)
  font_size = 3
  # font = ImageFont.truetype("arial.ttf", font_size)

  # Define text position (x, y)
  text_position = (0, 0)

  # Define text color (RGB)
  text_color = (0, 0, 0)  # White

  # Add text to the image
  draw.text(text_position, text, fill=text_color)
  save_to = generate_name()
  img.save(CUR_DIR + f"/flags/{save_to}.png")
  img = Image.open(CUR_DIR + f"/flags/{save_to}.png")
  os.remove(CUR_DIR + f"/flags/{save_to}.png")
  flag_bytes = fromPILImageToBytes(img)
  return flag_bytes

def create_rand_png():
  rand_name = generate_name()
  imarray = numpy.random.rand(100,100,3) * 255
  img = Image.fromarray(imarray.astype('uint8')).convert('RGBA')
  img.save(CUR_DIR + f"/images/{rand_name}.png")
  return rand_name

def create_rand_png_no_save():
  rand_name = generate_name()
  imarray = numpy.random.rand(100,100,3) * 255
  img = Image.fromarray(imarray.astype('uint8')).convert('RGBA')
  return img

def get_view(self, session, username):
  resp = session.get(f"http://{self.ip}:3000/view/{username}")
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Username: {username}\n- Resp Text: {resp.text}")
  return resp.text

def get_pub_img(self, session, num):
  resp = session.get(f"http://{self.ip}:3000/image/{num}")
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Image Url: http://{self.ip}:3000/image{num}\n- Resp Text: {resp.text}")
  return resp.text

def get_feed_pic_nums(self):
  resp = requests.get(f"http://{self.ip}:3000/feed")
  if resp.status_code != 200:
    raise ValueError(f"- Status Code: {resp.status_code}\n- Resp Text: {resp.text}")
  reg_text = r'<a href="/image/\d+">'
  nums = re.findall(reg_text, resp.text)
  if len(nums) == 0:
    return None
  return [int(i[16:][:-2]) for i in nums]


def logout(self):
  requests.get(f"http://{self.ip}:3000/auth/logout")

def fromPILImageToBytes(image):
    imageByteArray = io.BytesIO()
    image.save(imageByteArray,format="PNG")
    return imageByteArray.getvalue()

def fromBytesToPILImage(imageBytes):
    return Image.open(io.BytesIO(imageBytes))

def imageToStr(image):
    wrongType = checkExifData(image)
    if not wrongType:
        return wrongType
    image = str(base64.b64encode(image))[2:-1]
    return image

def checkExifData(image):
    pilImage = Image.open(io.BytesIO(image))
    if pilImage.format != "PNG":
        return False
    return True
