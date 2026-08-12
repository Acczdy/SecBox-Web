"""SecBox-Web 管理命令。"""
import argparse
import getpass
import sys

from runtime_secrets import generate_password, reset_oob_password, state_path, validate_password


def reset_password(args):
    password = args.password
    if not password:
        if not sys.stdin.isatty():
            raise SystemExit('非交互环境请使用 --password 指定密码')
        first = getpass.getpass('输入新的 OOB 访问密码（至少 12 位）: ')
        second = getpass.getpass('再次输入新密码: ')
        if first != second:
            raise SystemExit('两次输入的密码不一致')
        password = first
    validate_password(password)
    reset_oob_password(password)
    print('OOB 访问密码已重置；已有登录 Cookie 将立即失效。')
    print('密钥文件: {}'.format(state_path()))


def generate_and_reset(_args):
    password = generate_password()
    reset_oob_password(password)
    print('OOB 访问密码已重置为: {}'.format(password))
    print('请立即妥善保存；系统不会再次显示该密码。')


def main():
    parser = argparse.ArgumentParser(description='SecBox-Web 管理命令')
    subparsers = parser.add_subparsers(dest='command', required=True)
    reset = subparsers.add_parser('reset-oob-password', help='自定义重置 OOB 访问密码')
    reset.add_argument('--password', help='新密码；省略时安全交互输入')
    reset.set_defaults(handler=reset_password)
    random_reset = subparsers.add_parser('generate-oob-password', help='生成随机 OOB 密码并重置')
    random_reset.set_defaults(handler=generate_and_reset)
    args = parser.parse_args()
    args.handler(args)


if __name__ == '__main__':
    main()
