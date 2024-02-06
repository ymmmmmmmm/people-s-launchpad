# -*- coding: utf-8 -*-
# @Time     :2024/2/6 17:07
# @Author   :ym
# @File     :main.py
# @Software :PyCharm
import concurrent.futures
import hashlib
import json
import re
import time
import uuid
from base64 import b64encode

import requests
import tls_client
from eth_account import Account
from eth_account.messages import encode_defunct
from faker import Faker
from loguru import logger

from config import yescaptcha_client_key, get_ip_url

fake = Faker(locale='en-US')


def get_turnstile_token():
    while True:
        json_data = {
            "clientKey": yescaptcha_client_key,
            "task":
                {
                    "type": "TurnstileTaskProxylessM1",
                    "websiteURL": "https://launchpad.ally.build/zh-CN/signup",
                    "websiteKey": "0x4AAAAAAAPesjutGoykVbu0"
                }, "softID": 109
        }
        response = requests.post(url='https://api.yescaptcha.com/createTask', json=json_data).json()
        if response['errorId'] != 0:
            raise ValueError(response)
        task_id = response['taskId']
        time.sleep(5)
        for _ in range(30):
            data = {"clientKey": yescaptcha_client_key, "taskId": task_id}
            response = requests.post(url='https://api.yescaptcha.com/getTaskResult', json=data).json()
            if response['status'] == 'ready':
                return response['solution']['token']
            else:
                time.sleep(2)


def get_ip():
    response = requests.get(url=get_ip_url).text.strip()
    return {'http': f'http://{response}', 'https': f'http://{response}'}


def sha256(data):
    hash_object = hashlib.sha256()
    hash_object.update(json.dumps(data).replace(' ', '').encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig


def build_trackers(user_agent) -> str:
    return b64encode(json.dumps({"os": "Mac OS X", "browser": "Safari", "device": "", "system_locale": "zh-CN",
                                 "browser_user_agent": user_agent,
                                 "browser_version": "13.1.twitter_account", "os_version": "10.13.6", "referrer": "",
                                 "referring_domain": "", "referrer_current": "", "referring_domain_current": "",
                                 "release_channel": "stable", "client_build_number": 177662,
                                 "client_event_source": None}, separators=(',', ':')).encode()).decode()


def authorize_twitter(twitter_token, proxies=None):
    session = requests.session()
    session.proxies = proxies
    response = session.get(url='https://twitter.com/home', cookies={
        'auth_token': twitter_token,
        'ct0': '960eb16898ea5b715b54e54a8f58c172'
    })
    ct0 = re.findall('ct0=(.*?);', dict(response.headers)['set-cookie'])[0]
    cookies = {'ct0': ct0, 'auth_token': twitter_token}
    params = {
        'response_type': 'code',
        'client_id': 'TjkxNDIzc1ZscF9mSjU4Y3M0bkg6MTpjaQ',
        'redirect_uri': 'https://launchpad.ally.build/signup',
        'scope': 'tweet.read users.read',
        'state': f'twitter-{uuid.uuid4()}',
        'code_challenge': 'challenge',
        'code_challenge_method': 'plain',
    }

    headers = {'authority': 'twitter.com', 'accept': '*/*', 'accept-language': 'zh-CN,zh;q=0.9',
               'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
               'cache-control': 'no-cache', 'content-type': 'application/json', 'origin': 'https://twitter.com',
               'pragma': 'no-cache', 'referer': 'https://twitter.com/puffer_finance/status/1751954283052810298',
               'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
               'x-csrf-token': ct0}

    response = session.get('https://twitter.com/i/api/2/oauth2/authorize', params=params, cookies=cookies,
                           headers=headers).json()
    auth_code = response['auth_code']
    data = {'approval': True, 'code': auth_code}
    response = session.post('https://twitter.com/i/api/2/oauth2/authorize', json=data, cookies=cookies,
                            headers=headers).json()
    redirect_uri = response['redirect_uri']
    return redirect_uri


def authorize_discord(discord_token, proxies=None):
    session = tls_client.Session(
        random_tls_extension_order=True
    )
    session.proxies = proxies
    user_agent = fake.safari()
    headers = {
        'Host': 'discord.com',
        'Connection': 'keep-alive',
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }
    _uuid = uuid.uuid4()
    response = session.get(
        url=f'https://discord.com/api/oauth2/authorize?client_id=1189751301643456613&redirect_uri=https%3A%2F%2Flaunchpad.ally.build%2Fsignup&response_type=code&scope=identify%20email&state=discord-{_uuid}',
        headers=headers, allow_redirects=False)
    logger.debug(response)
    x_super_properties = build_trackers(user_agent)
    headers.update({"Authorization": discord_token})
    headers.update({"X-Super-Properties": x_super_properties})
    headers.update({"X-Debug-Options": 'bugReporterEnabled'})
    response = session.get(
        url=f'https://discord.com/oauth2/authorize?client_id=1189751301643456613&redirect_uri=https%3A%2F%2Flaunchpad.ally.build%2Fsignup&response_type=code&scope=identify%20email&state=discord-{_uuid}',
        headers=headers, allow_redirects=False)
    logger.debug(response.status_code)
    data = {"permissions": "0", "authorize": True, "integration_type": 0}
    response = session.post(
        url=f'https://discord.com/api/v9/oauth2/authorize?client_id=1189751301643456613&response_type=code&redirect_uri=https%3A%2F%2Flaunchpad.ally.build%2Fsignup&scope=identify%20email&state=discord-{_uuid}',
        headers=headers, allow_redirects=False, json=data).json()
    logger.debug(response)
    location = response['location']
    code = re.findall('code=(.*?)&state=', location)[0]
    return code


def run(twitter_token, discord_token, invite_code):
    try:
        account = Account.create()
        logger.debug(account.address)
        logger.debug(account.key.hex())
        device_id = str(uuid.uuid4())
        logger.debug(device_id)
        session = requests.Session()
        user_agent = fake.chrome()
        proxies = get_ip()
        session.proxies = proxies
        headers = {
            'authority': 'launchpad-api.particle.network',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'zh-CN,zh;q=0.9',
            'auth-type': 'Basic',
            'authorization': 'Basic SEJuRjRjOGlxU1FzUENtOTpMb1FGUmRyZTk0QmJmU0huR1NRTERIM0RC',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'origin': 'https://launchpad.ally.build',
            'pragma': 'no-cache',
            'referer': 'https://launchpad.ally.build/',
            'user-agent': user_agent,
        }
        random_str = str(uuid.uuid4())
        timestamp = int(time.time())
        params = {
            'timestamp': timestamp,
            'random_str': random_str,
            'device_id': device_id,
            'sdk_version': 'web_1.0.0',
            'project_uuid': 'aa93891b-14ee-4d92-be1a-f8bf4c9ef8b1',
            'project_client_key': 'cKqywDmiUAKvveMTyIW76i6argRwxtapjnQdPraZ',
            'project_app_uuid': '227102d9-5c30-455c-a03f-ed38e8fc893d',
        }
        sign_str = f"""Welcome to People's Launchpad!\n\nWallet address:\n{account.address}\n\nNonce:\n{device_id}"""
        signature = account.sign_message(encode_defunct(text=sign_str)).signature.hex()
        mac_info = {"device_id": device_id,
                    "loginInfo": {"address": account.address.lower(),
                                  "signature": signature},
                    "loginMethod": "evm_wallet",
                    "mac_key": "d2cf33cbf7808a428e8704e3217f0fff38873a8272c9ed58adb03a113d8ef95e",
                    "project_app_uuid": "227102d9-5c30-455c-a03f-ed38e8fc893d",
                    "project_client_key": "cKqywDmiUAKvveMTyIW76i6argRwxtapjnQdPraZ",
                    "project_uuid": "aa93891b-14ee-4d92-be1a-f8bf4c9ef8b1",
                    "random_str": random_str, "sdk_version": "web_1.0.0", "timestamp": timestamp}
        mac = sha256(dict(sorted(mac_info.items())))
        params.update({'mac': mac})
        json_data = {'loginMethod': 'evm_wallet',
                     'loginInfo': {'address': account.address.lower(), 'signature': signature}}
        response = session.post('https://launchpad-api.particle.network/global_user', params=params, headers=headers,
                                json=json_data).json()
        logger.debug(response)
        mac_key = response['macKey']
        token = response['token']
        headers.update({'authorization': f'Basic {token}'})
        # 操作绑定推特
        redirect_uri = authorize_twitter(twitter_token, proxies)
        twitter_code = redirect_uri.split('=')[2]
        response = session.get(redirect_uri, headers=headers)
        logger.debug(response.status_code)
        turnstile_token = get_turnstile_token()
        timestamp = int(time.time())
        random_str = str(uuid.uuid4())
        params = {
            "cfTurnstileResponse": turnstile_token,
            "code": twitter_code,
            "device_id": device_id, "mac_key": mac_key,
            "project_app_uuid": "227102d9-5c30-455c-a03f-ed38e8fc893d",
            "project_client_key": "cKqywDmiUAKvveMTyIW76i6argRwxtapjnQdPraZ",
            "project_uuid": "aa93891b-14ee-4d92-be1a-f8bf4c9ef8b1", "provider": "twitter",
            "random_str": random_str, "sdk_version": "web_1.0.0", "timestamp": timestamp}
        mac = sha256(dict(sorted(params.items())))
        params.update({'mac': mac})
        json_data = {"code": twitter_code,
                     "provider": "twitter",
                     "cfTurnstileResponse": turnstile_token}
        response = session.post('https://launchpad-api.particle.network/global_user/bind', params=params,
                                headers=headers,
                                json=json_data).json()
        logger.debug(response)
        if not response.get('twitterId', None):
            logger.warning(f'绑定推特失败')
            with open('twitter_fail.txt', 'a+') as f:
                f.writelines(f'{twitter_token}----{discord_token}----{invite_code}\n')
            return
        discord_code = authorize_discord(discord_token, proxies)
        turnstile_token = get_turnstile_token()
        timestamp = int(time.time())
        random_str = str(uuid.uuid4())
        params = {
            "cfTurnstileResponse": turnstile_token,
            "code": discord_code,
            "device_id": device_id, "mac_key": mac_key,
            "project_app_uuid": "227102d9-5c30-455c-a03f-ed38e8fc893d",
            "project_client_key": "cKqywDmiUAKvveMTyIW76i6argRwxtapjnQdPraZ",
            "project_uuid": "aa93891b-14ee-4d92-be1a-f8bf4c9ef8b1", "provider": "discord",
            "random_str": random_str, "sdk_version": "web_1.0.0", "timestamp": timestamp}
        mac = sha256(dict(sorted(params.items())))
        params.update({'mac': mac})
        json_data = {"code": discord_code,
                     "provider": "discord",
                     "cfTurnstileResponse": turnstile_token}
        response = session.post('https://launchpad-api.particle.network/global_user/bind', params=params,
                                headers=headers,
                                json=json_data).json()
        logger.debug(response)
        if not response.get('discordId', None):
            logger.warning(f'绑定discord失败')
            with open('discord_fail.txt', 'a+') as f:
                f.writelines(
                    f'{twitter_token}----{discord_token}----{invite_code}----{account.address}----{account.key.hex()}\n')
            return

        timestamp = int(time.time())
        random_str = str(uuid.uuid4())
        params = {"code": invite_code, "device_id": device_id,
                  "mac_key": mac_key,
                  "project_app_uuid": "227102d9-5c30-455c-a03f-ed38e8fc893d",
                  "project_client_key": "cKqywDmiUAKvveMTyIW76i6argRwxtapjnQdPraZ",
                  "project_uuid": "aa93891b-14ee-4d92-be1a-f8bf4c9ef8b1",
                  "random_str": random_str, "sdk_version": "web_1.0.0", "timestamp": timestamp}
        mac = sha256(dict(sorted(params.items())))
        params.update({'mac': mac})
        json_data = {'code': invite_code}
        response = session.post('https://launchpad-api.particle.network/launchpads/1/user', params=params,
                                headers=headers,
                                json=json_data).json()
        if response.get('invitationCode', None):
            logger.success(response)
            with open('success.txt', 'a+') as f:
                f.writelines(
                    f'{invite_code}----{twitter_token}----{discord_token}----{account.address}----{account.key.hex()}')
        else:
            logger.warning(response)
        return
    except Exception as e:
        logger.error(e)


def batch_run():
    """
    批量运行
    推特token----discordtoken----invite_code
    一行一个 ---- 隔开
    :return:
    """
    max_workers = 16
    with open('info_data.txt', 'r') as f:
        info_list = f.readlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(run, i.split('----')[0].replace('\n', ''), i.split('----')[1].replace('\n', ''),
                                   i.split('----')[2].replace('\n', '')) for i in info_list]


if __name__ == '__main__':
    _invite_code = '邀请码'
    _twitter_token = '推特token'
    _discord_token = 'discord token'
    run(_twitter_token, _discord_token, _invite_code)
