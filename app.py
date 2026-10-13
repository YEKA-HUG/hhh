assets = [
    {
        "资产名称": "业务服务器-Log4j",
        "IP地址": "192.168.1.50",
        "软件名称": "Apache Log4j",
        "版本号": "2.13"
    },
    {
        "资产名称": "测试服务器-Log4j",
        "IP地址": "192.168.1.51",
        "软件名称": "Apache Log4j",
        "版本号": "2.17"
    },
    {
        "资产名称": "Web服务器1",
        "IP地址": "192.168.1.10",
        "软件名称": "Apache",
        "版本号": "2.4.49"
    },
    {
        "资产名称": "Web服务器2",
        "IP地址": "192.168.1.11",
        "软件名称": "Nginx",
        "版本号": "1.18.0"
    },
    {
        "资产名称": "应用服务器1",
        "IP地址": "192.168.1.20",
        "软件名称": "Tomcat",
        "版本号": "9.0.56"
    },
    {
        "资产名称": "数据库服务器",
        "IP地址": "192.168.1.30",
        "软件名称": "MySQL",
        "版本号": "8.0.28"
    },
    {
        "资产名称": "办公服务器",
        "IP地址": "192.168.1.60",
        "软件名称": "Windows Server",
        "版本号": "2022"
    },
    {
        "资产名称": "安全管理服务器",
        "IP地址": "192.168.1.70",
        "软件名称": "Spring Boot",
        "版本号": "2.5"
    }
]

# 威胁情报研判平台最终整合版


import streamlit as st
import pandas as pd
import fitz
import re
from pathlib import Path
from textwrap import dedent
# =========================================================
# 1. 页面基础设置
# =========================================================
st.set_page_config(
    page_title="威胁情报研判平台",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================================================
# 2.文件保存目录
# =========================================================

UPLOAD_DIR = Path("data/uploads")

UPLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True
)

# =========================================================
# 3.保存上传文件
# =========================================================

def save_uploaded_file(uploaded_file):

    # 获取安全文件名
    safe_name = Path(uploaded_file.name).name

    # 文件最终保存位置
    save_path = UPLOAD_DIR / safe_name

    # 把上传的文件写入本地
    with open(save_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # 返回保存路径
    return save_path

# =========================================================
# 4. PDF解析函数
# =========================================================
def extract_pdf_text(pdf_path):
    """
    读取 PDF，并提取每一页的文字
    """

    document = fitz.open(pdf_path)

    all_text = []

    for page_number, page in enumerate(document, start=1):

        page_text = page.get_text("text")

        all_text.append(
            f"\n===== 第 {page_number} 页 =====\n"
            f"{page_text}"
        )

    document.close()

    return "\n".join(all_text)
# =========================================================
# CVE 漏洞编号提取函数
# =========================================================

def extract_cves(text):

    pattern = r"CVE-\d{4}-\d{4,7}"

    cves = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )

    # 统一转换成大写
    cves = [
        cve.upper()
        for cve in cves
    ]

    # 去重
    cves = list(dict.fromkeys(cves))

    return cves

# =========================================================
# IOC 攻击指标提取函数
# =========================================================

def extract_iocs(text):

    result = {
        "IP地址": [],
        "域名": [],
        "Hash": []
    }

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    result["IP地址"] = list(dict.fromkeys(re.findall(ip_pattern, text)))

    domain_pattern = r"\b[a-zA-Z0-9.-]+\.(?:com|net|org|cn|io)\b"
    result["域名"] = list(dict.fromkeys(re.findall(domain_pattern, text)))

    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
    result["Hash"] = list(dict.fromkeys(re.findall(hash_pattern, text)))

    return result



# =========================================================
# 影响对象实体提取函数
# =========================================================

def extract_objects(text):

    objects = {
        "软件": [],
        "组件": [],
        "操作系统": [],
        "应用框架": []
    }

    software_keywords = [
        "Apache Log4j",
        "Nginx",
        "Apache",
        "MySQL",
        "Redis",
        "OpenSSL",
        "Tomcat"
    ]

    component_keywords = [
        "log4j-core",
        "Log4j",
        "JNDI"
    ]

    os_keywords = [
        "Linux",
        "Windows Server",
        "Ubuntu",
        "CentOS"
    ]

    framework_keywords = [
        "Spring Boot",
        "Java",
        "Tomcat"
    ]

    for item in software_keywords:
        if item.lower() in text.lower():
            objects["软件"].append(item)

    for item in component_keywords:
        if item.lower() in text.lower():
            objects["组件"].append(item)

    for item in os_keywords:
        if item.lower() in text.lower():
            objects["操作系统"].append(item)

    for item in framework_keywords:
        if item.lower() in text.lower():
            objects["应用框架"].append(item)

    return objects


# =========================================================
# 攻击技术实体提取函数（增强版）
# =========================================================

def extract_attack_techniques(text):

    techniques = {
        "攻击技术": []
    }

    # 文本标准化，解决中英文空格、大小写导致匹配失败
    normalized_text = (
        text
        .replace(" ", "")
        .replace("　", "")
        .lower()
    )

    attack_rules = {
        "JNDI注入": [
            "jndi",
            "jndi注入",
            "jndi利用"
        ],

        "LDAP注入": [
            "ldap",
            "ldap注入",
            "ldap协议"
        ],

        "远程代码执行": [
            "远程代码执行",
            "remote code execution",
            "rce",
            "执行任意代码",
            "任意代码执行"
        ],

        "命令注入": [
            "命令注入",
            "command injection",
            "执行系统命令"
        ],

        "漏洞利用": [
            "漏洞利用",
            "exploit",
            "攻击者利用",
            "利用该漏洞"
        ],

        "恶意请求": [
            "恶意请求",
            "构造请求",
            "发送恶意请求"
        ],

        "反序列化攻击": [
            "反序列化",
            "deserialize"
        ],

        "文件上传攻击": [
            "文件上传",
            "上传恶意文件"
        ]
    }

    for attack_type, keywords in attack_rules.items():

        for keyword in keywords:

            if keyword.lower().replace(" ", "") in normalized_text:

                techniques["攻击技术"].append(
                    attack_type
                )

                break

    techniques["攻击技术"] = list(
        dict.fromkeys(
            techniques["攻击技术"]
        )
    )

    return techniques




# =========================================================
# 漏洞属性实体提取函数
# =========================================================

def extract_vulnerability_attributes(text):

    """
    漏洞属性识别：
    漏洞类型、风险等级、CVSS评分、攻击条件、攻击方式
    """

    attributes = {
        "漏洞类型": [],
        "风险等级": [],
        "CVSS评分": [],
        "攻击条件": [],
        "攻击方式": []
    }

    vulnerability_types = [
        "远程代码执行",
        "Remote Code Execution",
        "Remote Code Execution",
        "RCE",
        "SQL注入",
        "SQL Injection",
        "跨站脚本",
        "XSS",
        "文件上传漏洞",
        "反序列化漏洞",
        "目录遍历"
    ]

    risk_levels = [
        "严重",
        "Critical",
        "高危",
        "High",
        "中危",
        "Medium",
        "低危",
        "Low"
    ]

    attack_conditions = [
        "无需认证",
        "无需身份认证",
        "需要认证",
        "身份认证"
    ]

    attack_methods = [
        "远程攻击",
        "远程利用",
        "本地攻击",
        "本地利用"
    ]

    text_lower = text.lower()

    for item in vulnerability_types:
        if item.lower() in text_lower:
            attributes["漏洞类型"].append(item)

    for item in risk_levels:
        if item.lower() in text_lower:
            attributes["风险等级"].append(item)

    for item in attack_conditions:
        if item.lower() in text_lower:
            attributes["攻击条件"].append(item)

    for item in attack_methods:
        if item.lower() in text_lower:
            attributes["攻击方式"].append(item)

    scores = re.findall(
        r"CVSS(?:评分)?[：:\s]*(\d+(?:\.\d+)?)",
        text,
        flags=re.IGNORECASE
    )

    attributes["CVSS评分"].extend(scores)

    for key in attributes:
        attributes[key] = list(dict.fromkeys(attributes[key]))

    return attributes






# =========================================================
# 资产分析模块（升级版：CVE规则库 + 软件版本匹配）
# =========================================================

# 漏洞规则库
# 后续可以扩展为 json / 数据库
vulnerability_rules = {

    "CVE-2021-44228": {
        "影响软件": ["Apache Log4j", "Log4j"],
        "版本规则": "<=2.14",
        "漏洞类型": "远程代码执行",
        "风险等级": "Critical",
        "CVSS评分": "9.8",
        "处置建议": "升级 Apache Log4j 至安全版本（>=2.17.1）"
    },

    "CVE-2017-5638": {
        "影响软件": ["Apache Struts", "Struts"],
        "版本规则": "<=2.3.32",
        "漏洞类型": "远程代码执行",
        "风险等级": "High",
        "CVSS评分": "10.0",
        "处置建议": "升级 Apache Struts 至安全版本"
    },

    "CVE-2021-41773": {
        "影响软件": ["Apache"],
        "版本规则": "2.4.49",
        "漏洞类型": "路径穿越",
        "风险等级": "High",
        "CVSS评分": "9.8",
        "处置建议": "升级 Apache HTTP Server 至安全版本"
    }

}


# 内部资产库
asset_database = [
    {
        "资产名称": "业务服务器-Log4j",
        "IP地址": "192.168.1.50",
        "软件名称": "Apache Log4j",
        "版本号": "2.13"
    },
    {
        "资产名称": "测试服务器-Log4j",
        "IP地址": "192.168.1.51",
        "软件名称": "Apache Log4j",
        "版本号": "2.17"
    },
    {
        "资产名称": "Web服务器",
        "IP地址": "192.168.1.10",
        "软件名称": "Apache",
        "版本号": "2.4.49"
    },
    {
        "资产名称": "应用服务器",
        "IP地址": "192.168.1.20",
        "软件名称": "Tomcat",
        "版本号": "9.0.56"
    }
]


def version_to_float(version):

    try:
        parts = version.split(".")
        return float(".".join(parts[:2]))
    except:
        return None



def compare_version(asset_version, rule):

    """
    简单版本规则判断
    """

    version = version_to_float(asset_version)

    if version is None:
        return False


    if rule.startswith("<="):

        target = float(rule.replace("<=", ""))

        return version <= target


    elif rule.startswith("="):

        target = float(rule.replace("=", ""))

        return version == target


    return False




def analyze_asset_impact(objects, cves):
    """
    资产影响分析升级版：
    CVE + 影响对象 + 软件版本 + 漏洞属性联合分析
    """

    results = []

    rules = []

    for cve in cves:
        if cve in vulnerability_rules:
            rules.append(vulnerability_rules[cve])

    if not rules:
        rules = list(vulnerability_rules.values())


    for asset in asset_database:

        result = "未发现风险"
        reason = "未匹配漏洞影响范围"
        matched_cve = "-"
        vuln_type = "-"
        risk = "-"
        cvss = "-"
        suggestion = "-"


        for rule in rules:

            for software in rule["影响软件"]:

                if software.lower() in asset["软件名称"].lower():

                    if compare_version(
                        asset["版本号"],
                        rule["版本规则"]
                    ):

                        result = "受影响"

                        matched_cve = [
                            k for k,v in vulnerability_rules.items()
                            if v == rule
                        ][0]

                        vuln_type = rule["漏洞类型"]
                        risk = rule["风险等级"]
                        cvss = rule.get("CVSS评分","未知")
                        suggestion = rule.get("处置建议","建议升级补丁")

                        reason = (
                            f"匹配 {matched_cve}，"
                            f"{vuln_type}，"
                            f"版本满足 {rule['版本规则']}"
                        )

                    else:

                        result = "未发现风险"

                        reason = (
                            "软件匹配，但当前版本超过漏洞影响范围"
                        )


        results.append({

            "资产名称": asset["资产名称"],
            "IP地址": asset["IP地址"],
            "软件名称": asset["软件名称"],
            "版本号": asset["版本号"],
            "漏洞编号": matched_cve,
            "漏洞类型": vuln_type,
            "CVSS评分": cvss,
            "风险等级": risk,
            "影响结果": result,
            "判断依据": reason,
            "处置建议": suggestion

        })


    return pd.DataFrame(results)





if "current_pdf_text" not in st.session_state:
    st.session_state.current_pdf_text = ""

if "current_file_name" not in st.session_state:
    st.session_state.current_file_name = ""

if "current_file_path" not in st.session_state:
    st.session_state.current_file_path = ""

if "uploaded_records" not in st.session_state:
    st.session_state.uploaded_records = []
if "extracted_cves" not in st.session_state:
    st.session_state.extracted_cves = []

if "extracted_iocs" not in st.session_state:
    st.session_state.extracted_iocs = {}

if "extracted_objects" not in st.session_state:
    st.session_state.extracted_objects = {}

if "extracted_attack_techniques" not in st.session_state:
    st.session_state.extracted_attack_techniques = {}

if "extracted_vulnerability_attributes" not in st.session_state:
    st.session_state.extracted_vulnerability_attributes = {}
# =========================================================
# 2. 全局 CSS 样式
# =========================================================
st.markdown("""
<style>
    /* =====================================================
       隐藏 Streamlit 默认顶部栏，防止挡住所有页面标题
       ===================================================== */
    header[data-testid="stHeader"] {
        visibility: hidden !important;
        height: 0 !important;
        min-height: 0 !important;
    }

    div[data-testid="stToolbar"] {
        visibility: hidden !important;
        height: 0 !important;
    }

    #MainMenu {
        visibility: hidden !important;
    }

    footer {
        visibility: hidden !important;
    }

    /* 页面背景 */
    .stApp {
        background: #f4f7fb;
        color: #16324f;
    }

    /* 主内容区域：统一给首页和后面五页留出顶部空间 */
    .block-container {
        padding-top: 2.2rem !important;
        padding-bottom: 2rem !important;
        max-width: 1600px;
    }

    /* 左侧导航栏 */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a3a6f 0%, #062e5c 100%);
    }

    section[data-testid="stSidebar"] * {
        color: white !important;
    }

    section[data-testid="stSidebar"] .stRadio label {
        padding: 10px 12px;
        border-radius: 8px;
        margin-bottom: 2px;
    }

    section[data-testid="stSidebar"] .stRadio label:hover {
        background: rgba(45, 139, 255, 0.24);
    }

    /* 标题 */
    .page-title {
        font-size: 24px;
        font-weight: 800;
        color: #173b63;
        margin-top: 0 !important;
        margin-bottom: 6px;
        line-height: 1.4;
    }

    .sub-title {
        font-size: 16px;
        color: #607d9d;
        margin-bottom: 18px;
    }

    /* 顶部横幅 */
    .hero {
        background:
            radial-gradient(circle at 82% 30%, rgba(89, 176, 255, 0.42), transparent 20%),
            linear-gradient(120deg, #eaf5ff 0%, #cfe9ff 55%, #0b4a90 100%);
        border: 1px solid #d5e7f7;
        border-radius: 12px;
        padding: 24px 28px;
        min-height: 120px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 3px 10px rgba(23, 60, 99, 0.08);
    }

    .hero h1 {
        margin: 0 0 8px 0;
        color: #143f6b;
        font-size: 28px;
    }

    .hero p {
        margin: 0;
        color: #4d6680;
        font-size: 15px;
    }

    .hero-icon {
        font-size: 56px;
        filter: drop-shadow(0 6px 8px rgba(0,0,0,0.12));
    }

    /* 卡片 */
    .card {
        background: white;
        border: 1px solid #e6edf5;
        border-radius: 12px;
        padding: 18px;
        box-shadow: 0 2px 10px rgba(22, 50, 79, 0.06);
        height: 100%;
    }

    .card-title {
        font-size: 16px;
        font-weight: 800;
        color: #234568;
        margin-bottom: 14px;
    }

    .metric-card {
        background: white;
        border: 1px solid #e8eef5;
        border-radius: 10px;
        padding: 16px;
        min-height: 112px;
        box-shadow: 0 2px 8px rgba(22, 50, 79, 0.05);
    }

    .metric-label {
        color: #5f7590;
        font-size: 13px;
        margin-bottom: 8px;
    }

    .metric-value {
        font-size: 28px;
        font-weight: 800;
        color: #183f67;
    }

    .metric-change {
        color: #19a963;
        font-size: 12px;
        margin-top: 4px;
    }

    /* 状态标签 */
    .tag-green {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        background: #dff7e9;
        color: #159455;
        font-size: 12px;
        font-weight: 700;
    }

    .tag-blue {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        background: #e4f2ff;
        color: #1479d2;
        font-size: 12px;
        font-weight: 700;
    }

    .tag-red {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        background: #ffe5e5;
        color: #e04444;
        font-size: 12px;
        font-weight: 700;
    }

    .tag-orange {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        background: #fff0dc;
        color: #d98415;
        font-size: 12px;
        font-weight: 700;
    }

    /* 上传区域 */
    .upload-box {
        background: white;
        border: 2px dashed #c8d9ea;
        border-radius: 12px;
        padding: 28px;
        text-align: center;
        margin: 8px 0 20px 0;
    }

    /* PDF/详情模拟区 */
    .document-box {
        background: #fbfdff;
        border: 1px solid #e5edf5;
        border-radius: 10px;
        padding: 24px;
        min-height: 460px;
    }

    .document-box h2 {
        font-size: 22px;
        margin-top: 20px;
        margin-bottom: 18px;
        color: #1e3f61;
    }

    .document-box h3 {
        font-size: 17px;
        color: #254f76;
    }

    .document-box p {
        line-height: 1.9;
        color: #4b6379;
    }

    /* 进度环 */
    .circle-wrap {
        display: flex;
        align-items: center;
        gap: 18px;
        flex-wrap: wrap;
    }

    .circle {
        --p: 92;
        width: 88px;
        height: 88px;
        border-radius: 50%;
        background: conic-gradient(#24b86a calc(var(--p) * 1%), #e7eef6 0);
        display: grid;
        place-items: center;
        position: relative;
    }

    .circle::after {
        content: "";
        width: 66px;
        height: 66px;
        border-radius: 50%;
        background: white;
        position: absolute;
    }

    .circle span {
        z-index: 2;
        font-size: 17px;
        font-weight: 800;
        color: #244766;
    }

    .circle-label {
        font-size: 13px;
        color: #5d7186;
        margin-top: 6px;
        text-align: center;
    }

    /* 表格标题 */
    .section-title {
        font-size: 18px;
        font-weight: 800;
        color: #234b70;
        margin: 12px 0 8px 0;
    }

    /* Streamlit 按钮 */
    .stButton > button {
        border-radius: 8px;
        border: none;
        background: linear-gradient(90deg, #1685f8, #0a6ce5);
        color: white;
        font-weight: 700;
        padding: 0.55rem 1.2rem;
    }

    .stButton > button:hover {
        background: linear-gradient(90deg, #0d75dc, #095fc8);
        color: white;
        border: none;
    }

    div[data-testid="stFileUploader"] {
        background: white;
        border-radius: 10px;
        padding: 8px;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 10px;
        overflow: hidden;
    }

    .small-note {
        color: #7a8ca0;
        font-size: 12px;
    }
</style>
""", unsafe_allow_html=True)

# =========================================================
# 3. 左侧导航
# =========================================================
with st.sidebar:
    st.markdown("## 🛡️ 威胁情报研判平台")
    st.markdown("---")
    menu = st.radio(
        "导航",
        ["首页", "情报管理", "实体抽取", "资产分析", "结果展示", "系统评测"],
        label_visibility="collapsed"
    )
    st.markdown("---")
    st.caption("当前用户：admin")
    st.caption("前端演示版本 v1.0")

# =========================================================
# 4. 公共数据
# =========================================================
uploaded_files = pd.DataFrame({
    "文件名": ["漏洞通告.pdf", "CVE-2025-1234.html", "情报报告.docx"],
    "文件类型": ["PDF", "HTML", "DOCX"],
    "上传时间": ["2025-09-23 10:24", "2025-09-23 09:17", "2025-09-23 08:56"],
    "状态": ["解析完成", "解析中", "解析完成"]
})

entities = pd.DataFrame({
    "实体名称": ["CVE-2021-44228", "Apache Log4j", "JNDI", "Linux", "远程代码执行"],
    "类型": ["漏洞编号", "影响对象", "攻击技术", "影响对象", "漏洞属性"],
    "位置": ["第3段", "第2段", "第3段", "第5段", "第6段"],
    "置信度": ["98%", "96%", "92%", "87%", "85%"]
})

assets = pd.DataFrame({
    "资产名称": ["Web服务器1", "Web服务器2", "应用服务器1", "数据库服务器", "测试服务器"],
    "IP地址": ["192.168.1.10", "192.168.1.11", "192.168.1.20", "192.168.1.30", "192.168.1.40"],
    "软件名称": ["Apache", "Nginx", "Tomcat", "MySQL", "Apache"],
    "版本号": ["2.4.49", "1.18.0", "9.0.56", "8.0.28", "2.4.41"],
    "影响结果": ["受影响", "不受影响", "受影响", "疑似存在", "不受影响"],
    "风险等级": ["高危", "低危", "高危", "中危", "低危"]
})


# =========================================================
# 5. 首页
# =========================================================

if menu == "首页":

    st.markdown(
        dedent("""
        <div class="hero">
            <div>
                <h1>欢迎使用威胁情报研判平台</h1>
                <p>基于 Qwen 本地大模型的情报分析与资产影响评估系统</p>
            </div>

            🛡️
        </div>
        """),
        unsafe_allow_html=True
    )

    st.write("")

    c1, c2, c3, c4 = st.columns(4)

    metric_data = [
        ("📄 已汇聚文件", "128", "↑ 12%"),
        ("📑 已解析文本", "356", "↑ 10%"),
        ("🧠 识别实体", "1520", "↑ 23%"),
        ("🖥️ 影响资产", "86", "↑ 6%")
    ]

    for col, (label, value, change) in zip(
        [c1, c2, c3, c4],
        metric_data
    ):

        with col:

            st.markdown(
                dedent(f"""
                <div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                    <div class="metric-change">{change}</div>
                </div>
                """),
                unsafe_allow_html=True
            )

# =========================================================
# 6. 情报管理
# =========================================================

elif menu == "情报管理":

    st.markdown(
        '<div class="page-title">02. 情报管理 / 文件上传与解析</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="sub-title">'
        '当前阶段先实现 PDF 文件保存与正文解析'
        '</div>',
        unsafe_allow_html=True
    )


    # -----------------------------------------------------
    # 1. 上传提示区域
    # -----------------------------------------------------

    st.markdown(
        dedent("""
        <div class="upload-box">
            <div style="font-size:42px;">☁️</div>
            <div style="font-size:16px; font-weight:700; color:#31587b;">
                上传 PDF 情报文件
            </div>
            <div class="small-note" style="margin-top:6px;">
                PDF 将保存到本地，并自动提取正文
            </div>
        </div>
        """),
        unsafe_allow_html=True
    )


    # -----------------------------------------------------
    # 2. Streamlit 文件上传器
    # -----------------------------------------------------

    uploaded_file = st.file_uploader(

        "选择 PDF 文件",

        type=["pdf"],

        accept_multiple_files=False
    )


    # -----------------------------------------------------
    # 3. 保存并解析按钮
    # -----------------------------------------------------

    if uploaded_file is not None:

        st.info(
            f"已选择文件：{uploaded_file.name}"
        )

        if st.button(
            "保存并解析文件",
            use_container_width=False
        ):

            try:

                # -----------------------------------------
                # 第一步：保存 PDF
                # -----------------------------------------

                save_path = save_uploaded_file(
                    uploaded_file
                )


                # -----------------------------------------
                # 第二步：读取 PDF 正文
                # -----------------------------------------

                pdf_text = extract_pdf_text(
                    save_path
                )


                # -----------------------------------------
                # 第三步：保存到 session_state
                # -----------------------------------------

                st.session_state.current_file_name = (
                    uploaded_file.name
                )

                st.session_state.current_file_path = (
                    str(save_path)
                )

                st.session_state.current_pdf_text = (
                    pdf_text
                )


                # -----------------------------------------
                # 第四步：加入上传记录
                # -----------------------------------------

                record = {
                    "文件名": uploaded_file.name,
                    "文件类型": "PDF",
                    "保存位置": str(save_path),
                    "状态": "解析完成"
                }


                # 防止重复加入
                exists = False

                for item in st.session_state.uploaded_records:

                    if item["文件名"] == uploaded_file.name:

                        exists = True


                if not exists:

                    st.session_state.uploaded_records.append(
                        record
                    )


                st.success(
                    "文件保存并解析成功！"
                )


            except Exception as e:

                st.error(
                    f"文件解析失败：{e}"
                )


    # -----------------------------------------------------
    # 4. 已上传文件列表
    # -----------------------------------------------------

    st.write("")

    st.markdown(
        '<div class="section-title">'
        '已上传文件列表'
        '</div>',
        unsafe_allow_html=True
    )


    if len(st.session_state.uploaded_records) > 0:

        file_df = pd.DataFrame(
            st.session_state.uploaded_records
        )

        st.dataframe(
            file_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "暂时还没有上传文件。"
        )


    # -----------------------------------------------------
    # 5. 文件解析详情
    # -----------------------------------------------------

    st.divider()

    st.markdown(
        '<div class="page-title">'
        '文件解析详情'
        '</div>',
        unsafe_allow_html=True
    )


    # 判断有没有已经解析好的 PDF
    if st.session_state.current_pdf_text:

        left, right = st.columns(
            [1.7, 0.8]
        )


        # -------------------------------------------------
        # 左边：PDF 正文
        # -------------------------------------------------

        with left:

            st.markdown(
                '<div class="section-title">'
                '原始文件正文'
                '</div>',
                unsafe_allow_html=True
            )

            st.text_area(

                "PDF正文",

                value=st.session_state.current_pdf_text,

                height=500,

                disabled=True,

                label_visibility="collapsed"
            )


        # -------------------------------------------------
        # 右边：解析信息
        # -------------------------------------------------

        with right:

            text_length = len(
                st.session_state.current_pdf_text
            )

            st.markdown(
                dedent(f"""
                <div class="card">
                    <div class="card-title">解析结果</div>
                    <p><b>文件名称：</b>{st.session_state.current_file_name}</p>
                    <p><b>文件类型：</b>PDF</p>
                    <p><b>解析状态：</b><span class="tag-green">解析完成</span></p>
                    <p><b>正文长度：</b>{text_length} 字符</p>
                    <p><b>保存位置：</b>{st.session_state.current_file_path}</p>
                </div>
                """),
                unsafe_allow_html=True
            )


    else:

        st.info(
            "请先上传一个 PDF 文件并点击“保存并解析文件”。"
        )

# =========================================================
# 7. 实体抽取
# =========================================================
elif menu == "实体抽取":

    st.markdown(
        '<div class="page-title">03. 实体抽取 / 漏洞与IOC实体识别</div>',
        unsafe_allow_html=True
    )

    st.write("")

    if st.session_state.current_pdf_text:

        st.success(
            f"当前已解析文件：{st.session_state.current_file_name}"
        )

        if st.button("开始实体抽取"):

            st.session_state.extracted_cves = extract_cves(
                st.session_state.current_pdf_text
            )

            st.session_state.extracted_iocs = extract_iocs(
                st.session_state.current_pdf_text
            )

            # 提取影响对象（软件、组件、操作系统、应用框架）
            st.session_state.extracted_objects = extract_objects(
                st.session_state.current_pdf_text
            )

            # 提取攻击技术
            st.session_state.extracted_attack_techniques = extract_attack_techniques(
                st.session_state.current_pdf_text
            )

            # 提取漏洞属性
            st.session_state.extracted_vulnerability_attributes = extract_vulnerability_attributes(
                st.session_state.current_pdf_text
            )

            st.success("实体抽取完成！")

        st.write("")

        st.markdown(
            '<div class="section-title">CVE漏洞编号</div>',
            unsafe_allow_html=True
        )

        if st.session_state.extracted_cves:

            cve_df = pd.DataFrame({
                "序号": range(1, len(st.session_state.extracted_cves)+1),
                "实体名称": st.session_state.extracted_cves,
                "实体类型": ["漏洞编号"] * len(st.session_state.extracted_cves)
            })

            st.dataframe(cve_df, use_container_width=True, hide_index=True)

        else:
            st.info("暂无CVE编号")

        st.write("")

        st.markdown(
            '<div class="section-title">IOC攻击指标</div>',
            unsafe_allow_html=True
        )

        for kind, values in st.session_state.extracted_iocs.items():

            if values:
                df = pd.DataFrame({
                    "实体类型": [kind] * len(values),
                    "实体内容": values
                })

                st.dataframe(df, use_container_width=True, hide_index=True)

            else:
                st.info(f"{kind}：未发现")


        # ================================
        # 影响对象识别结果
        # ================================

        st.write("")

        st.markdown(
            '<div class="section-title">影响对象识别</div>',
            unsafe_allow_html=True
        )

        object_rows = []

        for obj_type, values in st.session_state.extracted_objects.items():

            for value in values:
                object_rows.append(
                    {
                        "实体类型": obj_type,
                        "实体内容": value
                    }
                )

        if object_rows:

            object_df = pd.DataFrame(object_rows)

            st.dataframe(
                object_df,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info("未识别到影响对象")


        # ================================
        # 攻击技术识别结果
        # ================================

        st.write("")

        st.markdown(
            '<div class="section-title">攻击技术识别</div>',
            unsafe_allow_html=True
        )

        attack_rows = []

        for tech_type, values in st.session_state.extracted_attack_techniques.items():

            for value in values:
                attack_rows.append(
                    {
                        "实体类型": tech_type,
                        "实体内容": value
                    }
                )

        if attack_rows:

            attack_df = pd.DataFrame(attack_rows)

            st.dataframe(
                attack_df,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info("未识别到攻击技术")

        # ================================
        # 漏洞属性识别结果
        # ================================

        st.write("")

        st.markdown(
            '<div class="section-title">漏洞属性识别</div>',
            unsafe_allow_html=True
        )


        attribute_rows = []


        for attr_type, values in st.session_state.extracted_vulnerability_attributes.items():

            for value in values:

                attribute_rows.append(
                    {
                        "属性类型": attr_type,
                        "属性内容": value
                    }
                )


        if attribute_rows:

            attribute_df = pd.DataFrame(attribute_rows)

            st.dataframe(
                attribute_df,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info("未识别到漏洞属性")




    else:

        st.warning("请先进入“情报管理”页面上传并解析 PDF。")


# =========================================================
# 8. 资产分析
# =========================================================
elif menu == "资产分析":

    st.markdown(
        '<div class="page-title">04. 资产影响分析</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="sub-title">根据漏洞情报中的影响对象、版本信息与内部资产进行关联分析</div>',
        unsafe_allow_html=True
    )


    if not st.session_state.current_pdf_text:

        st.warning(
            "请先上传漏洞PDF并完成实体抽取。"
        )

    else:

        st.markdown(
            '<div class="section-title">当前分析漏洞信息</div>',
            unsafe_allow_html=True
        )


        col1, col2 = st.columns(2)


        with col1:

            st.write(
                "影响对象："
            )

            if st.session_state.extracted_objects:

                for k,v in st.session_state.extracted_objects.items():
                    if v:
                        st.write(
                            f"{k}: {', '.join(v)}"
                        )

            else:
                st.info("请先完成实体抽取")


        with col2:

            st.write(
                "漏洞属性："
            )

            if st.session_state.extracted_vulnerability_attributes:

                for k,v in st.session_state.extracted_vulnerability_attributes.items():
                    if v:
                        st.write(
                            f"{k}: {', '.join(v)}"
                        )

            else:
                st.info("暂无漏洞属性")


        st.write("")


        if st.button(
            "开始资产影响分析",
            use_container_width=True
        ):

            result_df = analyze_asset_impact(
                st.session_state.extracted_objects,
                st.session_state.extracted_cves
            )

            st.session_state.asset_analysis_result = result_df


            st.success(
                "资产影响分析完成！"
            )


        st.markdown(
            '<div class="section-title">分析结果</div>',
            unsafe_allow_html=True
        )


        if "asset_analysis_result" in st.session_state:

            df = st.session_state.asset_analysis_result


            def color_result(value):
                if value == "受影响":
                    return "background-color:#ffe5e5"
                elif value == "不受影响":
                    return "background-color:#dff7e9"
                else:
                    return "background-color:#fff0dc"


            st.dataframe(
                df.style.map(
                    color_result,
                    subset=["影响结果"]
                ),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "点击开始分析按钮生成资产影响结果"
            )



# =========================================================
# 9. 结果展示
# =========================================================
elif menu == "结果展示":
    st.markdown('<div class="page-title">05. 结果展示 / 分析报告</div>', unsafe_allow_html=True)

    m1, m2, m3, m4 = st.columns(4)
    report_metrics = [
        ("漏洞名称", "CVE-2021-44228"),
        ("风险等级", "高危"),
        ("影响资产", "3 台"),
        ("生成时间", "2025-09-23 10:45")
    ]
    for c, (k, v) in zip([m1, m2, m3, m4], report_metrics):
        with c:
            st.markdown(
                dedent(f"""
                <div class="metric-card">
                    <div class="metric-label">{k}</div>
                    <div style="font-size:20px;font-weight:800;color:#1d456a;">{v}</div>
                </div>
                """),
                unsafe_allow_html=True
            )

    st.write("")
    left, right = st.columns([1.1, 1])

    with left:
        st.markdown(
            dedent("""
            <div class="card">
                <div class="card-title">漏洞详情</div>
                <p><b>漏洞编号：</b> CVE-2021-44228</p>
                <p><b>漏洞类型：</b> 远程代码执行</p>
                <p><b>影响组件：</b> Apache Log4j 2.x</p>
                <p><b>CVSS评分：</b> 9.8（严重）</p>
                <p><b>描述：</b> 攻击者可利用 JNDI 相关机制触发远程代码执行风险。</p>
                <p><b>攻击技术：</b>
                    <span class="tag-blue">T1100</span>
                    <span class="tag-blue">T1059</span>
                    <span class="tag-blue">T1203</span>
                </p>
            </div>
            """),
            unsafe_allow_html=True
        )

    with right:
        st.markdown('<div class="card-title">影响资产列表</div>', unsafe_allow_html=True)
        affected = assets.iloc[[0, 2, 3]][["资产名称", "IP地址", "软件名称", "版本号", "风险等级"]]
        st.dataframe(affected, use_container_width=True, hide_index=True)

        st.markdown(
            dedent("""
            <div class="card" style="margin-top:14px;">
                <div class="card-title">处置建议</div>
                <ol style="line-height:1.9;color:#4c6279;">
                    <li>立即升级 Log4j 至安全版本；</li>
                    <li>限制高风险服务的外部访问；</li>
                    <li>检查相关日志并持续监控异常行为。</li>
                </ol>
            </div>
            """),
            unsafe_allow_html=True
        )

    st.write("")
    st.button("导出分析报告")

# =========================================================
# 10. 系统评测
# =========================================================
elif menu == "系统评测":
    st.markdown(
        '<div class="page-title">06. 系统评测</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="section-title">模型效果评估</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3, c4 = st.columns(4)

    circles = [
        ("实体抽取 Micro-F1", 92, "#24b86a"),
        ("影响判断准确率", 88, "#278ff3"),
        ("实体证据一致率", 90, "#914df4")
    ]

    for col, (label, p, color) in zip([c1, c2, c3], circles):
        with col:
            st.markdown(
                dedent(f"""
                <div class="card" style="text-align:center;">
                    <div class="circle-wrap" style="justify-content:center;">
                        <div>
                            <div class="circle"
                                 style="--p:{p};background:conic-gradient({color} {p}%,#e7eef6 0);">
                                <span>{p}%</span>
                            </div>
                            <div class="circle-label">{label}</div>
                        </div>
                    </div>
                </div>
                """),
                unsafe_allow_html=True
            )

    with c4:
        st.markdown(
            dedent("""
            <div class="card">
                <div class="card-title">性能指标</div>
                <p>平均推理时间：<b>5.2s</b></p>
                <p>平均响应时间：<b>9.2s</b></p>
                <p>单条最快耗时：<b>6.7s</b></p>
                <p>系统可用性：<b>99.5%</b></p>
            </div>
            """),
            unsafe_allow_html=True
        )

    st.write("")
    left, right = st.columns([1.2, 1])

    with left:
        st.markdown(
            '<div class="section-title">任务统计</div>',
            unsafe_allow_html=True
        )

        stats = pd.DataFrame({
            "指标": ["总任务数", "已完成", "进行中", "警告", "失败"],
            "数量": [256, 240, 12, 12, 4]
        })

        st.dataframe(
            stats,
            use_container_width=True,
            hide_index=True,
            height=220
        )

    with right:
        st.markdown(
            '<div class="section-title">最近评测记录</div>',
            unsafe_allow_html=True
        )

        evaluate = pd.DataFrame({
            "时间": ["2025-09-23 10:30", "2025-09-22 16:12"],
            "评测内容": ["实体抽取评测", "资产风险评测"],
            "结果": ["92%", "88%"]
        })

        st.dataframe(
            evaluate,
            use_container_width=True,
            hide_index=True,
            height=220
        )
