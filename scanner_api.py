from fastapi import FastAPI
import subprocess
import os
import requests
import uvicorn

app = FastAPI()

# 核心配置：注意容器访问本地宿主机使用 host.docker.internal
DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://host.docker.internal:8080/api/v2/import-scan/")
DEFECTDOJO_TOKEN = os.getenv("DEFECTDOJO_TOKEN", "97e622b9e0dde514b4f6cfac0c6daf779dcdb541")
BASE_SCAN_DIR = "/app/scans"

@app.post("/scan")
def trigger_scan(payload: dict):
    target_url = payload.get("target_url")
    customer_name = payload.get("customer_name")
    month_str = payload.get("month_str", "Current")

    if not target_url or not customer_name:
        return {"status": "error", "message": "Missing parameters"}

    clean_name = "".join([c if c.isalnum() else "_" for c in customer_name])
    company_dir = os.path.join(BASE_SCAN_DIR, clean_name, month_str)
    os.makedirs(company_dir, exist_ok=True)
    output_path = os.path.join(company_dir, "scan_result.json")

    # 对齐 Pentest-Tools 的核心规则，加入伪装 UA 与必要参数
    cmd = [
        "nuclei",
        "-u", target_url,
        "-fr",                                              # 跟随重定向
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "-tags", "ssl,tls,misconfig,tech,exposure,cve",     # 全面对齐 Web、配置缺陷与 SSL
        "-c", "25",
        "-rate-limit", "150",
        "-timeout", "10",
        "-json-export", output_path
    ]
    subprocess.run(cmd)

    # 读取生成的扫描结果
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        file_content = "[]"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(file_content)
    else:
        with open(output_path, "r", encoding="utf-8") as f:
            file_content = f.read()

    # 自动导入 DefectDojo
    try:
        headers = {"Authorization": f"Token {DEFECTDOJO_TOKEN}"}
        data = {
            "scan_type": "Nuclei Scan",
            "product_name": customer_name,
            "product_type_name": "Research and Development",
            "engagement_name": f"{month_str} Audit",
            "auto_create_context": "true",                  # 自动创建不存在的 Product/Engagement
            "minimum_severity": "Info",
            "active": "true",
            "verified": "true",
            "close_old_findings": "false",
            "push_to_jira": "false"
        }
        files = {
            "file": (f"scan_result_{clean_name}_{month_str}.json", file_content.encode("utf-8"), "application/json")
        }
        res = requests.post(DEFECTDOJO_URL, headers=headers, data=data, files=files, timeout=30)
        print(f"DefectDojo response: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"DefectDojo upload error: {e}")

    # 返回原始 Nuclei 生成的 JSON 给 n8n
    return {
        "status": "success",
        "customer_name": customer_name,
        "json_data": file_content,
        "filename": f"scan_result_{clean_name}.json"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
