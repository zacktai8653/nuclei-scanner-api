from fastapi import FastAPI
import subprocess
import os
import requests
import uvicorn

app = FastAPI()

DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8080/api/v2/import-scan/")
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

    cmd = [
        "nuclei",
        "-u", target_url,
        "-fr",                            # 遵循重定向
        "-tags", "tech,misc,exposure,cve",# 覆盖面更广（技术栈、敏感信息、基础漏洞）
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "-c", "25",                       # 并发数
        "-rate-limit", "150",             # 限速，防止把小网站打死或触发安全拦截
        "-timeout", "10",                 # 超时时间拉长到 10 秒，适应网络慢的客户
        "-json-export", output_path
    ]
    subprocess.run(cmd)

    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        file_content = "[]"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(file_content)
    else:
        with open(output_path, "r", encoding="utf-8") as f:
            file_content = f.read()

    try:
        headers = {"Authorization": f"Token {DEFECTDOJO_TOKEN}"}
        data = {
            "scan_type": "Nuclei Scan",
            "product_name": customer_name,
            "product_type_name": "Research and Development",
            "engagement_name": f"{month_str} Audit",
            "auto_create_context": "true",
            "minimum_severity": "Info",
            "active": "true",
            "verified": "true"
        }
        files = {
            "file": (f"scan_result_{clean_name}_{month_str}.json", file_content.encode("utf-8"), "application/json")
        }
        requests.post(DEFECTDOJO_URL, headers=headers, data=data, files=files, timeout=15)
    except Exception as e:
        print(f"DefectDojo upload error: {e}")

    return {
        "status": "success",
        "customer_name": customer_name,
        "json_data": file_content,
        "filename": f"Nuclei_Scan_{clean_name}_{month_str}.json"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
