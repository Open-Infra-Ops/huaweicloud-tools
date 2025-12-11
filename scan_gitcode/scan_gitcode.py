# -*- coding: utf-8 -*-
# @Time    : 2025/12/10 16:21
# @Author  : Tom_zc
# @FileName: scan_gitcode.py
# @Software: PyCharm
import os
import sys
import textwrap
import traceback
from urllib.parse import quote

import click
import threading
import yaml
import smtplib
import time
import logging
import requests
import pandas as pd

from dataclasses import dataclass
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, wait
from email.mime.text import MIMEText
from email.header import Header


class Logger(object):
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'crit': logging.CRITICAL
    }

    def __init__(self, filename, level='info',
                 fmt='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'):
        self.logger = logging.getLogger(filename)
        format_str = logging.Formatter(fmt)
        self.logger.setLevel(self.level_relations.get(level))
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(format_str)
        self.logger.addHandler(sh)


logger = Logger('scan_gitcode.log').logger

_yaml_fields = ["scan_url", "scan_token", "gitcode_repo", "gitcode_token",
                "mta_sender", "mta_receivers", "mta_ip", "mta_port",
                "mta_username", "mta_password", "mta_subject"]

_ignore_file_list = ["png", "svg", "pdf", "gitmodules", "git", "ico", "drawio", "jpeg"]

_notify_div_template = textwrap.dedent("""
    <div>
    <p>亲:</p>
    <p>这是osInfra扫描中心，gitcode仓库敏感信息扫描结果如下图所示，共发现疑似包含敏感信息{}条，请及时处理：</p>
    <div class="table-detail">{}</div>
    </div>
""").strip()

_html_template = textwrap.dedent("""
<html>
<meta http-equiv="Content-Type" content="text/html;charset=UTF-8"/>
<head>
    <title>MindSpore</title>
    <style>

        table {
            border-collapse: collapse
        }

        th, td {
            border: 1px solid #000
        }

        .table-detail {
            left: 20px;
            bottom: 20px
        }
        
        td:nth-child(1), th:nth-child(1) { width: 100px; }
        td:nth-child(2), th:nth-child(2) { width: 100px; }
        td:nth-child(3), th:nth-child(3) { width: 100px; }
    </style>
</head>
<body>
{{template}}
</body>
</html>
""").strip()


@dataclass
class CommunityGitCode:
    gitcode_url: str
    gitcode_token: str
    scan_url: str
    scan_token: str


def func_retry(tries=5, delay=10):
    def deco_retry(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            for i in range(tries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    logger.info("e:{},traceback:{}".format(e, traceback.format_exc()))
                    time.sleep(delay)
            else:
                logger.info("func_retry: {} failed".format(fn.__name__))
                return None

        return inner

    return deco_retry


class ScanResult:
    _lock = threading.Lock()
    _scan_result = list()

    @classmethod
    def update_result(cls, list_data):
        if not isinstance(list_data, list):
            raise RuntimeError("update_result must be list")
        with cls._lock:
            cls._scan_result.extend(list_data)

    @property
    def result(self):
        return self._scan_result


class CountResult:
    _lock = threading.Lock()
    _count_result = list()

    @classmethod
    def update_result(cls, list_data):
        if not isinstance(list_data, list):
            raise RuntimeError("[CountResult] update_result must be list")
        with cls._lock:
            cls._count_result.extend(list_data)

    @property
    def result(self):
        return self._count_result


class AuditClient:
    def __init__(self, url=None, token=None, audit_type="OFFICIAL_WEBSITE"):
        self._url = url
        self._token = token
        self._audit_type = audit_type

    def _post_audit(self, content):
        headers = {
            "Content-Type": "application/json",
            "Token": self._token,
        }
        data = {
            "type": self._audit_type,
            "text": content
        }
        resp = requests.post(url=self._url, headers=headers, json=data)
        if not str(resp.status_code).startswith("20"):
            raise Exception("request audit:{}, and error msg:{}".format(str(resp.status_code), resp.content.decode()))
        return resp.json()

    def check_content_ok(self, content):
        if self._url is None or self._token is None:
            logger.info("AuditClient the url and token is not config")
            return True, ""
        try:
            json_data = self._post_audit(content)
        except Exception as e:
            logger.info("check the content failed:{}".format(e))
            return False, str(e)
        if json_data["data"]["result"] == "pass":
            return True, ""
        logger.info("check the content failed:{}".format(json_data))
        return False, json_data["data"]["exception"]


def get_gitcode_reject_describe(file_path, community_gitcode, result):
    reject_details = list()
    domain_html = "<a href='{0}'>{0}</a>".format(community_gitcode.gitcode_url)
    data = {
        "repo": domain_html,
        "pad_name": file_path,
        "reason": "block",
        "detail": result
    }
    reject_details.append(data)
    return reject_details


def split_string_by_batch(content, batch_size=1500):
    """使用列表推导式分批次"""
    return [content[i:i + batch_size]
            for i in range(0, len(content), batch_size)]


def scan_gitcode_repository(community_gitcode):
    """
    扫描单个gitcode仓库
    """
    if not isinstance(community_gitcode, CommunityGitCode):
        raise RuntimeError("community_gitcode must be CommunityGitCode")

    audit_client = AuditClient(community_gitcode.scan_url, community_gitcode.scan_token)
    scan_list = list()

    try:
        # 获取仓库中的文件列表和内容
        files_content = fetch_gitcode_repo_files(community_gitcode)

        for file_path, content in files_content.items():
            # 检查内容是否符合要求
            for split_content in split_string_by_batch(content):
                is_ok, err_msg = audit_client.check_content_ok(split_content)
                if not is_ok:
                    logger.info("Found sensitive content in {}".format(file_path))
                    scan_list.extend(get_gitcode_reject_describe(file_path, community_gitcode, err_msg))
    except Exception as e:
        logger.error("Error scanning gitcode repo {}: {}".format(community_gitcode.gitcode_url, e))

    scan_result = ScanResult()
    scan_result.update_result(scan_list)

    return scan_list


def get_file_lists(owner, repo, token):
    url = f"https://api.gitcode.com/api/v5/repos/{owner}/{repo}/file_list?access_token={token}"
    headers = {'Accept': 'application/json'}
    response = requests.request("GET", url, headers=headers)
    return response.json()


def get_content_by_path(owner, repo, path, token):
    encoded_safe = quote(path, safe='')
    url = f"https://api.gitcode.com/api/v5/repos/{owner}/{repo}/raw/{encoded_safe}?access_token={token}"
    headers = {'Accept': 'application/json'}
    response = requests.request("GET", url, headers=headers)
    return response.content.decode()


def fetch_gitcode_repo_files(community_gitcode):
    """
    从gitcode URL获取仓库文件内容
    注意：这需要根据实际的gitcode API进行调整
    """
    files_content = {}
    # 这里是示例实现，具体实现需要根据gitcode的实际API来完成
    # 可能需要使用community_gitcode.gitcode_token进行身份验证
    # 示例代码，需要替换为真实的API调用
    repo_list = community_gitcode.gitcode_url.split("/")
    owner = repo_list[-2]
    repo = repo_list[-1]
    files = get_file_lists(owner, repo, community_gitcode.gitcode_token)
    new_files = list()
    for file_path in files:
        file_suffix = file_path.split("/")[-1].split(".")[-1]
        if file_suffix in _ignore_file_list:
            logger.info("find the ignore file: {}".format(file_path))
            continue
        new_files.append(file_path)
    logger.info("find the count file list:{} | {}".format(community_gitcode.gitcode_url, len(new_files)))
    for file_path in new_files:
        try:
            logger.info("Fetching file: {}".format(file_path))
            content = get_content_by_path(owner, repo, file_path, community_gitcode.gitcode_token)
            files_content[file_path] = content
            time.sleep(0.2)
        except Exception as e:
            logger.error("Error fetching file: {}/{}".format(file_path, e))
    return files_content


def scan_repositories(config_obj):
    """
    扫描所有配置的仓库（包括gitcode）
    """
    executor = ThreadPoolExecutor(max_workers=20)
    all_tasks = []
    # 添加gitcode任务
    for community in config_obj["gitcode_repo"]:
        task = executor.submit(scan_gitcode_repository, CommunityGitCode(
            gitcode_url=community,
            gitcode_token=config_obj["gitcode_token"],
            scan_url=config_obj["scan_url"],
            scan_token=config_obj["scan_token"],
        ))
        all_tasks.append(task)
    wait(all_tasks)


# noinspection PyTypeChecker,SpellCheckingInspection
def generate_sensitive_html():
    cleaned_info = ScanResult().result
    cleaned_info = sorted(cleaned_info, key=lambda x: (x["repo"]), reverse=True)
    pd.set_option('display.width', 800)
    pd.set_option('display.max_colwidth', 150)
    pd.set_option('colheader_justify', 'center')
    pd.options.display.html.border = 2
    df = pd.DataFrame.from_dict(cleaned_info)
    df_style = df.style.hide()
    html = df_style.to_html()
    content = _notify_div_template.format(len(cleaned_info), html)
    template_content = _html_template.replace(r"{{template}}", content)
    return template_content


def send_email(config_obj):
    logger.info("----------start to send email---------")
    smtp_obj = smtplib.SMTP(config_obj["mta_ip"], config_obj["mta_port"])
    smtp_obj.login(config_obj["mta_username"], config_obj["mta_password"])
    receives = config_obj["mta_receivers"].split(";")
    text = generate_sensitive_html()
    message = MIMEText(text, "html", 'utf-8')
    message['Subject'] = Header(config_obj["mta_subject"], 'utf-8')
    message['To'] = ",".join(receives)
    smtp_obj.sendmail(config_obj["mta_sender"], receives, message.as_string())
    logger.info("----------end to send email---------")


def _parse_config(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _check_config(config_obj):
    fields = list(set(_yaml_fields) - set(config_obj.keys()))
    if fields:
        raise RuntimeError("lack the fields of:{}".format(",".join(fields)))

    # 检查gitcode配置
    if "community_gitcode" in config_obj:
        for community in config_obj["community_gitcode"]:
            if community.get("gitcode_url") is None:
                raise RuntimeError("lack the fields of gitcode_url.")


@click.command()
@click.option("--path", default="./config.yaml", help='The path of script config')
def main(path):
    config_path = os.getenv("CONFIG_PATH")
    if not config_path:
        config_path = path
    config_obj = _parse_config(config_path)
    _check_config(config_obj)
    scan_repositories(config_obj)
    send_email(config_obj)


if __name__ == '__main__':
    main()
