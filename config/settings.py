"""
전역 설정 및 환경 변수 관리
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# 프로젝트 루트 디렉토리
BASE_DIR = Path(__file__).resolve().parent.parent

# .env 파일 로드
load_dotenv(BASE_DIR / ".env")


class Config:
    """환경 변수 기반 설정 클래스"""

    # 네이버 URL
    NAVER_URL = os.getenv("NAVER_URL", "https://www.naver.com")
    NAVER_SHOPPING_URL = os.getenv("NAVER_SHOPPING_URL", "https://shopping.naver.com")

    # ADB 설정
    ADB_DEVICE_ID = os.getenv("ADB_DEVICE_ID", "")
    ADB_WIRELESS = os.getenv("ADB_WIRELESS", "false").lower() == "true"
    ADB_IP = os.getenv("ADB_IP", "")

    # 자동화 모드
    AUTOMATION_MODE = os.getenv("AUTOMATION_MODE", "adb")  # adb, appium, cdp
    APPIUM_SERVER = os.getenv("APPIUM_SERVER", "http://localhost:4723")
    CHROME_DEBUG_PORT = int(os.getenv("CHROME_DEBUG_PORT", "9222"))

    # 로깅
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE_ENABLED = os.getenv("LOG_FILE_ENABLED", "true").lower() == "true"
    LOG_FILE_PATH = BASE_DIR / os.getenv("LOG_FILE_PATH", "./logs/navertrafic.log")

    # 테스트 설정
    TEST_ITERATIONS = int(os.getenv("TEST_ITERATIONS", "100"))
    STAY_DURATION_MIN = int(os.getenv("STAY_DURATION_MIN", "30"))
    STAY_DURATION_MAX = int(os.getenv("STAY_DURATION_MAX", "60"))
    SCROLL_PROBABILITY = float(os.getenv("SCROLL_PROBABILITY", "0.7"))
    ACTION_WAIT_MIN = float(os.getenv("ACTION_WAIT_MIN", "2.0"))
    ACTION_WAIT_MAX = float(os.getenv("ACTION_WAIT_MAX", "5.0"))

    # 액션 확률 분포
    ACTION_CART_PROBABILITY = float(os.getenv("ACTION_CART_PROBABILITY", "0.3"))
    ACTION_REVIEW_PROBABILITY = float(os.getenv("ACTION_REVIEW_PROBABILITY", "0.4"))
    ACTION_QNA_PROBABILITY = float(os.getenv("ACTION_QNA_PROBABILITY", "0.2"))
    ACTION_BROWSE_PROBABILITY = float(os.getenv("ACTION_BROWSE_PROBABILITY", "0.1"))

    # IP 변경 설정
    AIRPLANE_MODE_DURATION = int(os.getenv("AIRPLANE_MODE_DURATION", "3"))
    NETWORK_RECONNECT_TIMEOUT = int(os.getenv("NETWORK_RECONNECT_TIMEOUT", "10"))
    VERIFY_IP_CHANGE = os.getenv("VERIFY_IP_CHANGE", "true").lower() == "true"

    # 순위 체크
    RANK_CHECK_DELAY = int(os.getenv("RANK_CHECK_DELAY", "1800"))
    RANK_CHECK_MAX_PAGE = int(os.getenv("RANK_CHECK_MAX_PAGE", "10"))

    # 데이터 저장
    DATA_STORAGE_TYPE = os.getenv("DATA_STORAGE_TYPE", "json")
    DATA_BACKUP_ENABLED = os.getenv("DATA_BACKUP_ENABLED", "true").lower() == "true"
    DATA_BACKUP_TIME = os.getenv("DATA_BACKUP_TIME", "00:00")

    # 성능 모니터링
    MONITOR_BATTERY = os.getenv("MONITOR_BATTERY", "true").lower() == "true"
    BATTERY_THRESHOLD = int(os.getenv("BATTERY_THRESHOLD", "20"))
    MONITOR_TEMPERATURE = os.getenv("MONITOR_TEMPERATURE", "true").lower() == "true"
    TEMPERATURE_THRESHOLD = int(os.getenv("TEMPERATURE_THRESHOLD", "45"))

    # 에러 핸들링
    MAX_RETRY_ATTEMPTS = int(os.getenv("MAX_RETRY_ATTEMPTS", "3"))
    RETRY_DELAY = int(os.getenv("RETRY_DELAY", "5"))

    # 개발 모드
    DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"
    SCREENSHOT_ON_ERROR = os.getenv("SCREENSHOT_ON_ERROR", "true").lower() == "true"
    DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

    # 디렉토리 경로
    CONFIG_DIR = BASE_DIR / "config"
    DATA_DIR = BASE_DIR / "data"
    LOGS_DIR = BASE_DIR / "logs"
    RANKINGS_DIR = DATA_DIR / "rankings"
    RESULTS_DIR = DATA_DIR / "results"

    # 테스트 상품 파일
    TEST_PRODUCTS_FILE = CONFIG_DIR / "test_products.json"

    @classmethod
    def validate(cls):
        """필수 설정 값 검증"""
        errors = []

        if not cls.ADB_DEVICE_ID and not cls.ADB_WIRELESS:
            errors.append("ADB_DEVICE_ID가 설정되지 않았습니다.")

        if cls.AUTOMATION_MODE not in ["adb", "appium", "cdp"]:
            errors.append(f"잘못된 AUTOMATION_MODE: {cls.AUTOMATION_MODE}")

        # 확률 합계 검증
        prob_sum = (
            cls.ACTION_CART_PROBABILITY +
            cls.ACTION_REVIEW_PROBABILITY +
            cls.ACTION_QNA_PROBABILITY +
            cls.ACTION_BROWSE_PROBABILITY
        )
        if abs(prob_sum - 1.0) > 0.01:
            errors.append(f"액션 확률의 합이 1.0이 아닙니다: {prob_sum}")

        if errors:
            raise ValueError("설정 오류:\n" + "\n".join(errors))

        return True


# 설정 인스턴스
config = Config()
