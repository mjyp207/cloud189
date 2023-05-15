import time
import re
import json
import base64
import hashlib
# from urllib import parse
import urllib.parse,hmac
import rsa
import requests
import random
 
 
# 常量定义
BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
 
 
# 定义日志系统
logger = getLogger(__name__)
logger.setLevel('INFO')
log_format = Formatter('[%(asctime)s] %(levelname)s : %(message)s')
 
console_handler = StreamHandler()
console_handler.setLevel('INFO')
console_handler.setFormatter(log_format)
logger.addHandler(console_handler)
 
log_path = Path('logs')
log_path.mkdir(parents=True, exist_ok=True)
log_file = log_path / f'{time.strftime("%Y%m%d")}.log'
file_handler = FileHandler(log_file, mode='a', encoding='utf-8')
file_handler.setLevel('DEBUG')
file_handler.setFormatter(log_format)
logger.addHandler(file_handler)
 
 
# 定义工具函数
def int2char(a: int) -> str:
    return BI_RM[a]
 
 
def b64tohex(a: str) -> str:
    a += '=='[(len(a) % 4):]
    data = base64.b64decode(a)
    return data.hex()
 
 
def sign_params(params: str, secret_key: str) -> str:
    sign = f"{params}{secret_key}"
    md5 = hashlib.md5(sign.encode('utf-8')).hexdigest()
    return md5
 
 
def encode_rsa_public_key(n: int, e: int) -> str:
    public_numbers = RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key(backend=default_backend())
    pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = pem.decode().strip().split('\n')[1:-1]
    pem = ''.join(pem)
    return pem
 
 
def rsa_encode(j_rsakey: str, string: str) -> str:
    numbers = json.loads(j_rsakey)
    public_key = encode_rsa_public_key(numbers['n'], numbers['e'])
    public_key = serialization.load_pem_public_key(public_key.encode(), backend=default_backend())
    ciphertext = public_key.encrypt(string.encode(), padding.PKCS1v15())
    result = ciphertext.hex()
    return result
 
 
# 定义登陆函数
def login(username: str, password: str, timeout: int = 10) -> requests.Session:
    url_token = "https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html"
    url_contacts = "https://api.cloud.189.cn/mkt/userSign.action?rand=0.34093141047311375"
 
    headers = {
        'Accept-Encoding': 'gzip',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; SM-G9750 Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/94.0.4606.61 Mobile Safari/537.36 MCloudApp/7.4.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Referer': 'https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html'
    }
 
    # 获取加密参数
    try:
        resp = requests.get(url_token, headers=headers, timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception('Failed to get token parameters')
        raise
 
    params_str = re.findall(r'params: \'(.+)\',', resp.text)[0]
    secret_key = re.findall(r'secretKey: \'(.+)\',', resp.text)[0]
    j_rsakey = re.findall(r'j_rsakey" value=\'(.+)\'>', resp.text)[0]
    sid = re.findall(r"mCloud_sid = '(.+)';", resp.text)[0]
 
    # 加密账号和密码
    params = {
        'appId': '',
        'accountType': '01',
        'userName': rsa_encode(j_rsakey, username),
        'password': rsa_encode(j_rsakey, password),
        'validateCode': '',
        'smsCode': '',
        'mailCode': '',
        'isOauth2': 'false',
        'clientType': 'android',
        'cb_SaveName': '0',
        'mailSuffix': '@189.cn',
        'deviceId': '',
        'umidToken': '',
        'tkFlag': 'true',
        'returnUrl': '',
        'showType': '03',
        'redirectURL': 'https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html',
        'state': '',
        'param': '',
        'hdfs_device_id': '',
        'mCloud_sid': sid
    }
 
    params['sign'] = sign_params(json.dumps(params, separators=(',', ':')), secret_key)
 
    # 登录
    session = requests.session()
    try:
        resp = session.post(url_token, headers=headers, data=base64.b64encode(json.dumps(params).encode()).decode(), timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception('Failed to login')
        raise
     
    if resp.json().get('result') != '0':
        logger.error('Failed to login: %s', resp.json())
        raise RuntimeError('Failed to login')
     
    logger.info('Login successfully')
 
    return session
 
 
# 定义签到函数
def sign_in(session: requests.Session, timeout: int = 10) -> Dict[str, int]:
    url_sign_in = "https://api.cloud.189.cn/mkt/userSign.action?rand=0.34093141047311375"
    url_lottery = "https://api.cloud.189.cn/mkt/lottery.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
    url_reward_info = "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=21&activityId=ACT_SIGNIN"
    url_message = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=ENTER_YOUR_KEY"
 
    headers = {
        'Accept-Encoding': 'gzip',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; SM-G9750 Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/94.0.4606.61 Mobile Safari/537.36 MCloudApp/7.4.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Referer': 'https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html'
    }
 
    # 签到
    try:
        resp = session.get(url_sign_in, headers=headers, timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception('Failed to sign in')
        raise
 
    resp_json = resp.json()
    if resp_json.get('isSign') == 'Y':
        logger.info('Already signed in')
    elif resp_json.get('signFlag') == '1':
        logger.info('Signed in successfully')
    else:
        msg = f"Failed to sign in: {resp_json.get('msg')}"
        logger.warning(msg)
 
    # 抽奖
    rewards = {}
    for i in range(3):
        try:
            resp_lottery = session.get(url_lottery, headers=headers, timeout=timeout)
            resp_lottery.raise_for_status()
        except requests.exceptions.RequestException:
            logger.exception('Failed to draw lottery')
            raise
         
        resp_reward_info = session.get(url_reward_info, headers=headers, timeout=timeout)
        resp_reward_info.raise_for_status()
 
        resp_json = resp_reward_info.json()
        name = resp_json['giftList'][i]['giftName']
        num = int(resp_json['giftList'][i]['giftNum'])
        rewards[name] = num
 
        logger.info('Draw lottery: %s x %d', name, num)
 
    # 发送企业微信消息
    message = f"天翼云盘签到：已签到\n\n"
    for name, num in rewards.items():
        message += f"- {name} x {num}\n"
    message = message.strip()
 
    params = {
        "msgtype": "text",
        "text": {
            "content": message
        }
    }
 
    try:
        resp = requests.post(url_message, json=params, timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception('Failed to send wechat message')
        raise
 
    logger.info('Send wechat message successfully')
 
    return rewards
 
 
# 定义主函数
def main(username: str, password: str, timeout: int = 10) -> None:
    with login(username, password, timeout=timeout) as session:
        rewards = sign_in(session, timeout=timeout)
 
    logger.info('Sign in finish: %s', rewards)
 
 
if __name__ == '__main__':
    main(username, password)
