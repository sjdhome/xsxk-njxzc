#!/usr/bin/env python3

import base64
import sys
import json

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 网络等待时间。
TIMEOUT = 3

# config.json格式
#
# {
#   "username": "21111111",
#   "password": "1145141919810"
# }


# 获取验证码，验证码会输出到当前文件夹的captcha.png里。
def get_captcha() -> tuple[str, str]:
    req = requests.post("http://xsxk.njxzc.edu.cn/xsxk/auth/captcha", timeout=TIMEOUT)
    result = req.json()
    if req.status_code != 200 or result["code"] != 200:
        print("获取验证码失败")
        print(result)
        sys.exit(1)
    uuid = result["data"]["uuid"]
    captcha_img_base64: str = result["data"]["captcha"][len("data:image/png;base64,") :]
    captcha_img = base64.b64decode(captcha_img_base64)
    with open("captcha.png", "wb") as file:
        file.write(captcha_img)
    captcha = input("输入看到的验证码：")
    return uuid, captcha


# 登录时提交的密码需要AES ECB加密，密钥就在登录页面的HTML文件里。
def encrypt_password(password: str) -> bytes:
    cipher = Cipher(
        algorithms.AES("MWMqg2tPcDkxcm11".encode()),
        modes.ECB(),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()  # type: ignore
    padded_password = padder.update(password.encode()) + padder.finalize()
    encrypted_password = encryptor.update(padded_password)
    final_password = base64.b64encode(encrypted_password)
    return final_password


# 登录流程。
def login(username: str, password: str) -> str:
    uuid, captcha = get_captcha()
    encrypted_password = encrypt_password(password)
    response = requests.post(
        "http://xsxk.njxzc.edu.cn/xsxk/auth/login",
        params={
            "loginname": username,
            "password": encrypted_password,
            "captcha": captcha.lower(),
            "uuid": uuid,
        },
        timeout=TIMEOUT,
    )
    result = response.json()
    if response.status_code != 200 or result["code"] != 200:
        print("登录失败")
        print(result)
        sys.exit(2)
    print("登录成功")
    token = result["data"]["token"]
    print(f"学号: {result['data']['student']['XH']}")
    print(f"姓名: {result['data']['student']['XM']}")
    batch_list = result["data"]["student"]["electiveBatchList"]
    if len(batch_list) != 1:
        print("请选择选课批次：")
        for index, name in batch_list:
            print(f"{index}: {name}")
        batch = batch_list[int(input(": "))]
    else:
        batch = batch_list[0]
    print(f"选课批次: {batch['name']}")
    response = requests.post(
        "http://xsxk.njxzc.edu.cn/xsxk/elective/user",
        headers={"Authorization": token},
        params={"batchId": batch["code"]},
        timeout=TIMEOUT,
    )
    result = response.json()
    if response.status_code != 200 or result["code"] != 200:
        print("选择选课批次失败")
        print(result)
        sys.exit(3)
    return token


def add_class(classType: str, className: str):
    pass


def main():
    with open("config.json", encoding="utf-8") as file:
        config = json.load(file)
    # token = login(config["username"], config["password"])
    for _, clazz in enumerate(config["class"]):
        add_class(clazz["type"], clazz["name"])


if __name__ == "__main__":
    main()
