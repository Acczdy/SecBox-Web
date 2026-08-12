"""报告解析（fscan / mimikatz）路由

说明：解析逻辑完全在浏览器前端执行，粘贴的扫描结果与凭据内容
不会上传到服务器（敏感内容不出页面）。
"""
from flask import Blueprint, render_template

parser_bp = Blueprint('parser', __name__, url_prefix='/parser')


@parser_bp.route('')
def index():
    """报告解析页面"""
    return render_template('tools/scan_parser.html', title='报告解析')
