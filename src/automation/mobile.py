"""
ADB 모바일 제어 모듈
"""
import subprocess
import time
import re
from typing import Optional, List, Tuple
from pathlib import Path
from config.settings import config
from src.utils.logger import log


class ADBController:
    """ADB를 통한 Android 기기 제어 클래스"""

    def __init__(self, device_id: Optional[str] = None):
        """
        Args:
            device_id: ADB 기기 ID (None이면 config에서 가져옴)
        """
        self.device_id = device_id or config.ADB_DEVICE_ID
        self._verify_adb_installed()

        if self.device_id:
            self._verify_device_connected()

    def _verify_adb_installed(self):
        """ADB 설치 확인"""
        try:
            result = subprocess.run(
                ["adb", "version"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                version = result.stdout.split('\n')[0]
                log.info(f"ADB 확인 완료: {version}")
            else:
                raise Exception("ADB 버전 확인 실패")

        except FileNotFoundError:
            log.error("ADB가 설치되지 않았습니다. PATH에 ADB를 추가하세요.")
            raise
        except Exception as e:
            log.error(f"ADB 확인 실패: {e}")
            raise

    def _verify_device_connected(self):
        """기기 연결 확인"""
        devices = self.list_devices()

        if not devices:
            log.error("연결된 기기가 없습니다.")
            raise Exception("ADB 기기 연결 안됨")

        if self.device_id not in devices:
            log.error(f"기기 ID '{self.device_id}'를 찾을 수 없습니다.")
            log.info(f"연결된 기기: {devices}")
            raise Exception(f"기기 ID '{self.device_id}' 연결 안됨")

        log.success(f"기기 연결 확인: {self.device_id}")

    def _run_adb_command(
        self,
        command: List[str],
        timeout: int = 30,
        check: bool = True
    ) -> subprocess.CompletedProcess:
        """
        ADB 명령어 실행

        Args:
            command: ADB 명령어 리스트
            timeout: 타임아웃 (초)
            check: 실패 시 예외 발생 여부

        Returns:
            subprocess.CompletedProcess
        """
        # 기기 ID가 있으면 -s 옵션 추가
        if self.device_id:
            full_command = ["adb", "-s", self.device_id] + command
        else:
            full_command = ["adb"] + command

        log.debug(f"ADB 명령 실행: {' '.join(full_command)}")

        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check
            )

            if result.returncode == 0:
                log.debug(f"명령 성공: {result.stdout.strip()}")
            else:
                log.warning(f"명령 실패 (코드 {result.returncode}): {result.stderr.strip()}")

            return result

        except subprocess.TimeoutExpired:
            log.error(f"명령 타임아웃: {' '.join(full_command)}")
            raise
        except subprocess.CalledProcessError as e:
            log.error(f"명령 실패: {e.stderr}")
            raise
        except Exception as e:
            log.error(f"명령 실행 오류: {e}")
            raise

    def list_devices(self) -> List[str]:
        """
        연결된 기기 목록 조회

        Returns:
            기기 ID 리스트
        """
        result = self._run_adb_command(["devices"], check=False)

        devices = []
        for line in result.stdout.split('\n')[1:]:  # 첫 줄 "List of devices attached" 제외
            line = line.strip()
            if line and '\t' in line:
                device_id, status = line.split('\t')
                if status == 'device':
                    devices.append(device_id)

        log.info(f"연결된 기기: {devices}")
        return devices

    def get_device_info(self) -> dict:
        """
        기기 정보 조회

        Returns:
            기기 정보 딕셔너리
        """
        info = {}

        # 제조사
        result = self._run_adb_command(["shell", "getprop", "ro.product.manufacturer"], check=False)
        info["manufacturer"] = result.stdout.strip()

        # 모델명
        result = self._run_adb_command(["shell", "getprop", "ro.product.model"], check=False)
        info["model"] = result.stdout.strip()

        # Android 버전
        result = self._run_adb_command(["shell", "getprop", "ro.build.version.release"], check=False)
        info["android_version"] = result.stdout.strip()

        # 화면 해상도
        result = self._run_adb_command(["shell", "wm", "size"], check=False)
        match = re.search(r'(\d+)x(\d+)', result.stdout)
        if match:
            info["screen_width"] = int(match.group(1))
            info["screen_height"] = int(match.group(2))

        # 배터리 정보
        result = self._run_adb_command(["shell", "dumpsys", "battery"], check=False)
        battery_match = re.search(r'level: (\d+)', result.stdout)
        if battery_match:
            info["battery_level"] = int(battery_match.group(1))

        log.info(f"기기 정보: {info.get('manufacturer')} {info.get('model')} (Android {info.get('android_version')})")
        return info

    # ==================== 네트워크 제어 ====================

    def enable_airplane_mode(self) -> bool:
        """
        비행기모드 활성화

        Returns:
            성공 여부
        """
        log.info("비행기모드 활성화 중...")

        try:
            # Android 6.0 이상
            self._run_adb_command([
                "shell", "cmd", "connectivity", "airplane-mode", "enable"
            ])

            log.success("비행기모드 활성화 완료")
            return True

        except Exception as e:
            log.error(f"비행기모드 활성화 실패: {e}")

            # 대체 방법 (Android 5.x 이하)
            try:
                log.info("대체 방법 시도...")
                self._run_adb_command([
                    "shell", "settings", "put", "global", "airplane_mode_on", "1"
                ])
                self._run_adb_command([
                    "shell", "am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE",
                    "--ez", "state", "true"
                ])
                log.success("비행기모드 활성화 완료 (대체 방법)")
                return True
            except Exception as e2:
                log.error(f"대체 방법도 실패: {e2}")
                return False

    def disable_airplane_mode(self) -> bool:
        """
        비행기모드 비활성화

        Returns:
            성공 여부
        """
        log.info("비행기모드 비활성화 중...")

        try:
            # Android 6.0 이상
            self._run_adb_command([
                "shell", "cmd", "connectivity", "airplane-mode", "disable"
            ])

            log.success("비행기모드 비활성화 완료")
            return True

        except Exception as e:
            log.error(f"비행기모드 비활성화 실패: {e}")

            # 대체 방법
            try:
                log.info("대체 방법 시도...")
                self._run_adb_command([
                    "shell", "settings", "put", "global", "airplane_mode_on", "0"
                ])
                self._run_adb_command([
                    "shell", "am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE",
                    "--ez", "state", "false"
                ])
                log.success("비행기모드 비활성화 완료 (대체 방법)")
                return True
            except Exception as e2:
                log.error(f"대체 방법도 실패: {e2}")
                return False

    def toggle_airplane_mode(self, duration: int = 3) -> bool:
        """
        비행기모드 토글 (IP 변경용)

        Args:
            duration: 비행기모드 유지 시간 (초)

        Returns:
            성공 여부
        """
        log.info(f"비행기모드 토글 시작 (유지시간: {duration}초)")

        # 비행기모드 ON
        if not self.enable_airplane_mode():
            return False

        # 대기
        log.info(f"{duration}초 대기 중...")
        time.sleep(duration)

        # 비행기모드 OFF
        if not self.disable_airplane_mode():
            return False

        log.success("비행기모드 토글 완료")
        return True

    def wait_for_network(self, timeout: int = 30) -> bool:
        """
        네트워크 재연결 대기

        Args:
            timeout: 최대 대기 시간 (초)

        Returns:
            연결 성공 여부
        """
        log.info(f"네트워크 재연결 대기 중 (최대 {timeout}초)...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                # 네트워크 연결 상태 확인
                result = self._run_adb_command([
                    "shell", "dumpsys", "connectivity"
                ], check=False)

                # WiFi 또는 Mobile 연결 확인
                if "NetworkAgentInfo" in result.stdout and "CONNECTED" in result.stdout:
                    elapsed = time.time() - start_time
                    log.success(f"네트워크 재연결 완료 ({elapsed:.1f}초)")
                    return True

                time.sleep(1)

            except Exception as e:
                log.debug(f"네트워크 확인 중 오류: {e}")
                time.sleep(1)

        log.error(f"네트워크 재연결 타임아웃 ({timeout}초)")
        return False

    def get_ip_address(self) -> Optional[str]:
        """
        기기 IP 주소 조회

        Returns:
            IP 주소 또는 None
        """
        try:
            result = self._run_adb_command([
                "shell", "ip", "addr", "show", "wlan0"
            ], check=False)

            # inet 192.168.x.x/24 형태에서 IP 추출
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                ip = match.group(1)
                log.debug(f"현재 IP: {ip}")
                return ip

            return None

        except Exception as e:
            log.error(f"IP 조회 실패: {e}")
            return None

    # ==================== 화면 제어 ====================

    def tap(self, x: int, y: int) -> bool:
        """
        화면 탭

        Args:
            x: X 좌표
            y: Y 좌표

        Returns:
            성공 여부
        """
        log.debug(f"화면 탭: ({x}, {y})")

        try:
            self._run_adb_command([
                "shell", "input", "tap", str(x), str(y)
            ])
            return True
        except Exception as e:
            log.error(f"탭 실패: {e}")
            return False

    def swipe(
        self,
        x1: int, y1: int,
        x2: int, y2: int,
        duration: int = 300
    ) -> bool:
        """
        스와이프 (드래그)

        Args:
            x1, y1: 시작 좌표
            x2, y2: 끝 좌표
            duration: 스와이프 시간 (ms)

        Returns:
            성공 여부
        """
        log.debug(f"스와이프: ({x1}, {y1}) → ({x2}, {y2}), {duration}ms")

        try:
            self._run_adb_command([
                "shell", "input", "swipe",
                str(x1), str(y1),
                str(x2), str(y2),
                str(duration)
            ])
            return True
        except Exception as e:
            log.error(f"스와이프 실패: {e}")
            return False

    def scroll_down(self, duration: int = 300) -> bool:
        """
        아래로 스크롤

        Args:
            duration: 스크롤 시간 (ms)

        Returns:
            성공 여부
        """
        # 화면 중앙 기준 스크롤
        device_info = self.get_device_info()
        width = device_info.get("screen_width", 1080)
        height = device_info.get("screen_height", 1920)

        x = width // 2
        y1 = int(height * 0.7)  # 화면 70% 지점
        y2 = int(height * 0.3)  # 화면 30% 지점

        return self.swipe(x, y1, x, y2, duration)

    def scroll_up(self, duration: int = 300) -> bool:
        """
        위로 스크롤

        Args:
            duration: 스크롤 시간 (ms)

        Returns:
            성공 여부
        """
        device_info = self.get_device_info()
        width = device_info.get("screen_width", 1080)
        height = device_info.get("screen_height", 1920)

        x = width // 2
        y1 = int(height * 0.3)
        y2 = int(height * 0.7)

        return self.swipe(x, y1, x, y2, duration)

    def input_text(self, text: str) -> bool:
        """
        텍스트 입력

        Args:
            text: 입력할 텍스트 (공백은 %s로 변환됨)

        Returns:
            성공 여부
        """
        # 공백을 %s로 변환 (ADB input 명령어 요구사항)
        text = text.replace(" ", "%s")

        log.debug(f"텍스트 입력: {text}")

        try:
            self._run_adb_command([
                "shell", "input", "text", text
            ])
            return True
        except Exception as e:
            log.error(f"텍스트 입력 실패: {e}")
            return False

    def press_key(self, keycode: int) -> bool:
        """
        키 입력

        Args:
            keycode: Android KeyEvent 코드
                     - 3: HOME
                     - 4: BACK
                     - 66: ENTER
                     - 82: MENU
                     - 24: VOLUME_UP
                     - 25: VOLUME_DOWN

        Returns:
            성공 여부
        """
        log.debug(f"키 입력: {keycode}")

        try:
            self._run_adb_command([
                "shell", "input", "keyevent", str(keycode)
            ])
            return True
        except Exception as e:
            log.error(f"키 입력 실패: {e}")
            return False

    def press_home(self) -> bool:
        """홈 버튼"""
        return self.press_key(3)

    def press_back(self) -> bool:
        """뒤로가기 버튼"""
        return self.press_key(4)

    def press_enter(self) -> bool:
        """엔터 키"""
        return self.press_key(66)

    # ==================== 앱 제어 ====================

    def open_url(self, url: str) -> bool:
        """
        URL 열기 (Chrome 브라우저)

        Args:
            url: 열 URL

        Returns:
            성공 여부
        """
        log.info(f"URL 열기: {url}")

        try:
            self._run_adb_command([
                "shell", "am", "start",
                "-a", "android.intent.action.VIEW",
                "-d", url
            ])
            log.success(f"URL 열기 완료: {url}")
            return True
        except Exception as e:
            log.error(f"URL 열기 실패: {e}")
            return False

    def launch_app(self, package_name: str, activity_name: str = None) -> bool:
        """
        앱 실행

        Args:
            package_name: 패키지명 (예: com.android.chrome)
            activity_name: 액티비티명 (선택)

        Returns:
            성공 여부
        """
        log.info(f"앱 실행: {package_name}")

        try:
            if activity_name:
                component = f"{package_name}/{activity_name}"
            else:
                component = package_name

            self._run_adb_command([
                "shell", "am", "start", "-n", component
            ])
            log.success(f"앱 실행 완료: {package_name}")
            return True
        except Exception as e:
            log.error(f"앱 실행 실패: {e}")
            return False

    # ==================== 유틸리티 ====================

    def take_screenshot(self, output_path: Optional[Path] = None) -> Optional[Path]:
        """
        스크린샷 저장

        Args:
            output_path: 저장 경로 (None이면 자동 생성)

        Returns:
            저장된 파일 경로 또는 None
        """
        if output_path is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = config.BASE_DIR / "screenshots" / f"screenshot_{timestamp}.png"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        log.info(f"스크린샷 저장 중: {output_path}")

        try:
            # 기기에 스크린샷 저장
            device_path = "/sdcard/screenshot_temp.png"
            self._run_adb_command([
                "shell", "screencap", "-p", device_path
            ])

            # PC로 복사
            self._run_adb_command([
                "pull", device_path, str(output_path)
            ])

            # 기기에서 삭제
            self._run_adb_command([
                "shell", "rm", device_path
            ])

            log.success(f"스크린샷 저장 완료: {output_path}")
            return output_path

        except Exception as e:
            log.error(f"스크린샷 실패: {e}")
            return None

    def wake_screen(self) -> bool:
        """화면 켜기"""
        log.debug("화면 켜기")

        try:
            # 화면 상태 확인
            result = self._run_adb_command([
                "shell", "dumpsys", "power"
            ], check=False)

            if "mWakefulness=Asleep" in result.stdout or "mScreenOn=false" in result.stdout:
                # 화면이 꺼져있으면 전원 버튼 누르기
                self.press_key(26)  # POWER
                time.sleep(0.5)

            return True
        except Exception as e:
            log.error(f"화면 켜기 실패: {e}")
            return False


# 편의 함수
def get_controller(device_id: Optional[str] = None) -> ADBController:
    """ADBController 인스턴스 생성 편의 함수"""
    return ADBController(device_id)


if __name__ == "__main__":
    # 테스트
    controller = ADBController()

    print("\n=== 기기 정보 ===")
    info = controller.get_device_info()
    for key, value in info.items():
        print(f"{key}: {value}")

    print("\n=== IP 주소 ===")
    ip = controller.get_ip_address()
    print(f"IP: {ip}")
