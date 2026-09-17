# -*- coding: utf-8 -*-
"""应用入口

启动方式（M6 会提供 run.bat 一键化）：
    .venv\\Scripts\\python.exe app.py
访问：
    http://127.0.0.1:5000
"""
from config import Config
from secplat import create_app

app = create_app()

if __name__ == "__main__":
    print("=" * 56)
    print(f"  网络安全检测平台 已启动：http://{Config.HOST}:{Config.PORT}")
    print("  登录账号见 config.py（默认 admin / admin123，请及时修改）")
    print("=" * 56)
    app.run(host=Config.HOST, port=Config.PORT, threaded=True, debug=False)
