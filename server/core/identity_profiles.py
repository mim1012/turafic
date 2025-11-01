"""
Identity Profile Management
신원 프로필 관리 - User-Agent, 쿠키, 브라우저 지문 등
"""

from sqlalchemy import Column, String, JSON, DateTime, Integer
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid

Base = declarative_base()


class IdentityProfile(Base):
    """신원 프로필 테이블"""
    __tablename__ = "identity_profiles"
    
    profile_id = Column(String(36), primary_key=True)  # UUID
    group_name = Column(String(50), index=True, nullable=False)  # 예: "samsung_mobile_default"
    name = Column(String(100), nullable=False)  # 프로필 이름 (예: "Galaxy S22 Profile 1")
    
    # 신원 정보
    user_agent = Column(String(500), nullable=False)
    cookies = Column(JSON, nullable=True)  # [{"name": "NID", "value": "..."}]
    headers = Column(JSON, nullable=True)  # {"Accept-Language": "ko-KR,ko;q=0.9"}
    fingerprint = Column(JSON, nullable=True)  # {"screen_resolution": "1080x2340", "webgl_vendor": "..."}
    
    # 메타 정보
    created_at = Column(DateTime, default=datetime.utcnow)
    usage_count = Column(Integer, default=0)  # 사용 횟수 추적


# 기본 신원 프로필 생성 함수
def create_default_samsung_profiles():
    """
    기본 삼성 모바일 프로필 생성
    
    Returns:
        List[IdentityProfile]: 생성된 프로필 리스트
    """
    profiles = []
    
    # 삼성 기기 모델 및 Android 버전 조합
    devices = [
        ("SM-S901N", "12", "1080x2340", "Samsung Exynos"),  # Galaxy S22
        ("SM-A235N", "11", "1080x2400", "Qualcomm Adreno"),  # Galaxy A23
        ("SM-N960N", "10", "1440x2960", "ARM Mali"),  # Galaxy Note 9
        ("SM-G996N", "12", "1080x2400", "Samsung Exynos"),  # Galaxy S21+
        ("SM-F926N", "11", "1768x2208", "Qualcomm Adreno"),  # Galaxy Z Fold 3
    ]
    
    for idx, (model, android_ver, resolution, webgl_vendor) in enumerate(devices, 1):
        # 각 기기당 3개의 프로필 생성 (총 15개)
        for variant in range(1, 4):
            profile_id = str(uuid.uuid4())
            
            # User-Agent 생성
            chrome_ver = f"96.0.{4664 + variant}.104"  # Chrome 버전 약간씩 다르게
            user_agent = (
                f"Mozilla/5.0 (Linux; Android {android_ver}; {model}) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) "
                f"SamsungBrowser/17.0 Chrome/{chrome_ver} Mobile Safari/537.36"
            )
            
            # 쿠키 (네이버 NID 예시 - 실제로는 유효한 쿠키 필요)
            cookies = [
                {"name": "NID_AUT", "value": f"dummy_aut_{profile_id[:8]}"},
                {"name": "NID_SES", "value": f"dummy_ses_{profile_id[:8]}"},
            ]
            
            # 헤더
            headers = {
                "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
            }
            
            # 브라우저 지문
            fingerprint = {
                "screen_resolution": resolution,
                "webgl_vendor": webgl_vendor,
                "canvas_hash": f"hash_{profile_id[:12]}",  # 실제로는 Canvas fingerprint 계산 필요
                "timezone": "Asia/Seoul",
                "language": "ko-KR",
            }
            
            profile = IdentityProfile(
                profile_id=profile_id,
                group_name="samsung_mobile_default",
                name=f"{model} Profile {variant}",
                user_agent=user_agent,
                cookies=cookies,
                headers=headers,
                fingerprint=fingerprint
            )
            
            profiles.append(profile)
    
    return profiles
