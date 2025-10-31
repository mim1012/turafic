"""
로깅 유틸리티
"""
import sys
from pathlib import Path
from loguru import logger
from config.settings import config


def setup_logger():
    """로거 초기화 및 설정"""
    # 기본 로거 제거
    logger.remove()

    # 콘솔 출력 설정
    logger.add(
        sys.stdout,
        level=config.LOG_LEVEL,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        colorize=True,
    )

    # 파일 로깅 설정
    if config.LOG_FILE_ENABLED:
        # 로그 디렉토리 생성
        config.LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

        # 일반 로그 파일
        logger.add(
            config.LOG_FILE_PATH,
            level=config.LOG_LEVEL,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            rotation="100 MB",  # 100MB마다 로테이션
            retention="30 days",  # 30일 보관
            compression="zip",  # 압축 저장
            encoding="utf-8",
        )

        # 에러 로그 별도 파일
        error_log_path = config.LOG_FILE_PATH.parent / "error.log"
        logger.add(
            error_log_path,
            level="ERROR",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}\n{exception}",
            rotation="50 MB",
            retention="60 days",
            compression="zip",
            encoding="utf-8",
        )

    return logger


# 로거 초기화
log = setup_logger()


def log_function_call(func):
    """함수 호출 로깅 데코레이터"""
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        log.debug(f"함수 호출: {func_name}(args={args}, kwargs={kwargs})")
        try:
            result = func(*args, **kwargs)
            log.debug(f"함수 완료: {func_name} -> {result}")
            return result
        except Exception as e:
            log.error(f"함수 에러: {func_name} -> {e}")
            raise
    return wrapper


if __name__ == "__main__":
    # 테스트
    log.debug("디버그 메시지")
    log.info("정보 메시지")
    log.warning("경고 메시지")
    log.error("에러 메시지")
    log.success("성공 메시지")
