"""
Appium 환경 검증 스크립트

설치 상태 및 의존성을 확인하고 문제점을 진단합니다.
"""
import sys
import subprocess
import os
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.append(str(Path(__file__).parent.parent))

from src.utils.logger import get_logger

log = get_logger()


class AppiumVerifier:
    """Appium 환경 검증기"""

    def __init__(self):
        self.checks_passed = 0
        self.checks_failed = 0
        self.warnings = []

    def verify_all(self) -> bool:
        """모든 검증 수행"""
        log.info("\n" + "="*80)
        log.info("Appium 환경 검증 시작")
        log.info("="*80 + "\n")

        checks = [
            ("Node.js", self.check_nodejs),
            ("NPM", self.check_npm),
            ("Appium", self.check_appium),
            ("Appium Drivers", self.check_appium_drivers),
            ("Python Appium Client", self.check_python_appium),
            ("Android SDK", self.check_android_sdk),
            ("ADB", self.check_adb),
            ("Emulator", self.check_emulator),
            ("환경 변수", self.check_env_vars),
        ]

        for check_name, check_func in checks:
            log.info(f"[{check_name}] 검증 중...")
            try:
                result = check_func()
                if result:
                    log.success(f"  ✅ {check_name} 정상")
                    self.checks_passed += 1
                else:
                    log.error(f"  ❌ {check_name} 실패")
                    self.checks_failed += 1
            except Exception as e:
                log.error(f"  ❌ {check_name} 오류: {e}")
                self.checks_failed += 1

        # 최종 결과
        log.info("\n" + "="*80)
        log.info("검증 결과")
        log.info("="*80)
        log.info(f"통과: {self.checks_passed}/{len(checks)}")
        log.info(f"실패: {self.checks_failed}/{len(checks)}")

        if self.warnings:
            log.warning(f"\n경고 사항 ({len(self.warnings)}개):")
            for warning in self.warnings:
                log.warning(f"  ⚠️ {warning}")

        if self.checks_failed == 0:
            log.success("\n✅ 모든 검증 통과! Appium 사용 준비 완료.")
            return True
        else:
            log.error(f"\n❌ {self.checks_failed}개 항목 실패. 문서를 참조하여 설치하세요.")
            log.info("\n📖 설치 가이드: APPIUM_SETUP_GUIDE.md")
            log.info("📖 빠른 시작: QUICK_START_APPIUM.md")
            return False

    def check_nodejs(self) -> bool:
        """Node.js 설치 확인"""
        try:
            result = subprocess.run(
                ['node', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                log.debug(f"    Node.js 버전: {version}")

                # 버전 체크 (v16.0.0 이상 권장)
                version_num = version.replace('v', '').split('.')[0]
                if int(version_num) < 16:
                    self.warnings.append(f"Node.js {version}은 너무 오래되었습니다. v16+ 권장")

                return True
            return False
        except FileNotFoundError:
            log.error("    Node.js가 설치되지 않았습니다.")
            log.info("    설치: https://nodejs.org")
            return False

    def check_npm(self) -> bool:
        """NPM 설치 확인"""
        try:
            result = subprocess.run(
                ['npm', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                log.debug(f"    NPM 버전: {version}")
                return True
            return False
        except FileNotFoundError:
            log.error("    NPM이 설치되지 않았습니다.")
            return False

    def check_appium(self) -> bool:
        """Appium 설치 확인"""
        try:
            result = subprocess.run(
                ['appium', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                log.debug(f"    Appium 버전: {version}")

                # 버전 체크 (2.0.0 이상 권장)
                version_num = version.split('.')[0]
                if int(version_num) < 2:
                    self.warnings.append(f"Appium {version}은 구버전입니다. v2.0+ 권장")

                return True
            return False
        except FileNotFoundError:
            log.error("    Appium이 설치되지 않았습니다.")
            log.info("    설치: npm install -g appium")
            return False

    def check_appium_drivers(self) -> bool:
        """Appium 드라이버 설치 확인"""
        try:
            result = subprocess.run(
                ['appium', 'driver', 'list', '--installed'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.lower()

                if 'uiautomator2' in output:
                    log.debug("    uiautomator2 드라이버 설치됨")
                    return True
                else:
                    log.error("    uiautomator2 드라이버가 설치되지 않았습니다.")
                    log.info("    설치: appium driver install uiautomator2")
                    return False
            return False
        except Exception as e:
            log.error(f"    드라이버 확인 실패: {e}")
            return False

    def check_python_appium(self) -> bool:
        """Python Appium 클라이언트 설치 확인"""
        try:
            import appium
            version = appium.__version__
            log.debug(f"    Appium-Python-Client 버전: {version}")
            return True
        except ImportError:
            log.error("    Appium-Python-Client가 설치되지 않았습니다.")
            log.info("    설치: pip install Appium-Python-Client")
            return False

    def check_android_sdk(self) -> bool:
        """Android SDK 설치 확인"""
        android_home = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')

        if not android_home:
            log.error("    ANDROID_HOME 환경 변수가 설정되지 않았습니다.")
            log.info("    설정: C:\\Users\\사용자명\\AppData\\Local\\Android\\Sdk")
            return False

        sdk_path = Path(android_home)
        if not sdk_path.exists():
            log.error(f"    Android SDK 경로가 존재하지 않습니다: {android_home}")
            return False

        log.debug(f"    Android SDK 경로: {android_home}")

        # platform-tools 확인
        platform_tools = sdk_path / "platform-tools"
        if not platform_tools.exists():
            self.warnings.append("platform-tools 디렉토리가 없습니다.")

        return True

    def check_adb(self) -> bool:
        """ADB 설치 확인"""
        try:
            result = subprocess.run(
                ['adb', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                log.debug(f"    {version_line}")
                return True
            return False
        except FileNotFoundError:
            log.error("    ADB가 설치되지 않았거나 PATH에 없습니다.")
            log.info("    Android SDK platform-tools를 PATH에 추가하세요.")
            return False

    def check_emulator(self) -> bool:
        """Android Emulator 설치 확인"""
        try:
            result = subprocess.run(
                ['emulator', '-version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                log.debug(f"    {version_line}")
                return True
            return False
        except FileNotFoundError:
            log.error("    Android Emulator가 설치되지 않았거나 PATH에 없습니다.")
            log.info("    Android Studio에서 설치하거나 PATH에 추가하세요.")
            return False

    def check_env_vars(self) -> bool:
        """필수 환경 변수 확인"""
        required_vars = ['ANDROID_HOME', 'ANDROID_SDK_ROOT']
        optional_vars = ['JAVA_HOME']

        has_android = False
        for var in required_vars:
            value = os.environ.get(var)
            if value:
                log.debug(f"    {var}: {value}")
                has_android = True
                break

        if not has_android:
            log.error("    ANDROID_HOME 또는 ANDROID_SDK_ROOT가 설정되지 않았습니다.")
            return False

        # JAVA_HOME 확인 (선택)
        java_home = os.environ.get('JAVA_HOME')
        if not java_home:
            self.warnings.append("JAVA_HOME이 설정되지 않았습니다. (필수 아님)")
        else:
            log.debug(f"    JAVA_HOME: {java_home}")

        return True

    def check_avds(self):
        """생성된 AVD 목록 확인"""
        log.info("\n" + "="*80)
        log.info("생성된 에뮬레이터(AVD) 확인")
        log.info("="*80 + "\n")

        try:
            result = subprocess.run(
                ['emulator', '-list-avds'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                avds = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

                if avds:
                    log.success(f"총 {len(avds)}개 AVD 발견:")
                    for avd in avds:
                        if 'Emulator_PC_' in avd:
                            log.info(f"  ✅ {avd}")
                        else:
                            log.debug(f"  - {avd}")
                else:
                    log.warning("생성된 AVD가 없습니다.")
                    log.info("\nAVD 생성:")
                    log.info("  powershell -File scripts/create_emulators_quick.ps1")
            else:
                log.error("AVD 목록 확인 실패")

        except Exception as e:
            log.error(f"AVD 확인 중 오류: {e}")


def main():
    """메인 함수"""
    verifier = AppiumVerifier()

    # 환경 검증
    all_passed = verifier.verify_all()

    # AVD 확인 (선택적)
    try:
        verifier.check_avds()
    except:
        pass

    # 다음 단계 안내
    if all_passed:
        log.info("\n" + "="*80)
        log.info("다음 단계")
        log.info("="*80)
        log.info("\n1. 에뮬레이터 생성 (5개):")
        log.info("   powershell -ExecutionPolicy Bypass -File scripts/create_emulators_quick.ps1")
        log.info("\n2. Appium 서버 시작:")
        log.info("   appium")
        log.info("\n3. 테스트 실행:")
        log.info("   python run_appium_test.py --instances 5 --iterations 3")
        log.info("\n📖 상세 가이드: QUICK_START_APPIUM.md\n")
    else:
        log.info("\n" + "="*80)
        log.info("설치 가이드")
        log.info("="*80)
        log.info("\n1. 상세 설치 가이드:")
        log.info("   APPIUM_SETUP_GUIDE.md 참조")
        log.info("\n2. 빠른 시작:")
        log.info("   QUICK_START_APPIUM.md 참조")
        log.info("\n3. 문제 해결:")
        log.info("   APPIUM_SETUP_GUIDE.md의 '트러블슈팅' 섹션 참조\n")


if __name__ == "__main__":
    main()
