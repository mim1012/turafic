"""
ADB 제어 모듈 테스트 스크립트

사용법:
  1. Android 기기를 USB로 연결
  2. USB 디버깅 활성화
  3. python test_adb_controller.py 실행
"""
import time
from src.automation.mobile import ADBController
from src.utils.logger import log


def print_menu():
    """메뉴 출력"""
    print("\n" + "=" * 60)
    print("ADB 제어 모듈 테스트")
    print("=" * 60)
    print("\n【기본 정보】")
    print("  1. 연결된 기기 목록 조회")
    print("  2. 기기 정보 조회")
    print("  3. IP 주소 조회")
    print("\n【네트워크 제어】")
    print("  4. 비행기모드 ON")
    print("  5. 비행기모드 OFF")
    print("  6. 비행기모드 토글 (IP 변경)")
    print("  7. 네트워크 재연결 대기")
    print("\n【화면 제어】")
    print("  8. 화면 탭 테스트")
    print("  9. 스크롤 다운 테스트")
    print("  10. 스크롤 업 테스트")
    print("  11. 텍스트 입력 테스트")
    print("\n【앱 제어】")
    print("  12. 네이버 열기")
    print("  13. 네이버 쇼핑 열기")
    print("  14. Chrome 브라우저 실행")
    print("  15. 홈 버튼")
    print("  16. 뒤로가기 버튼")
    print("\n【유틸리티】")
    print("  17. 스크린샷 저장")
    print("  18. 화면 켜기")
    print("\n【종합 테스트】")
    print("  99. 전체 기능 자동 테스트")
    print("\n  0. 종료")
    print("=" * 60)


def test_basic_info(controller):
    """기본 정보 테스트"""
    print("\n" + "-" * 60)
    print("【기기 정보】")
    info = controller.get_device_info()
    for key, value in info.items():
        print(f"  {key}: {value}")

    print("\n【IP 주소】")
    ip = controller.get_ip_address()
    print(f"  IP: {ip or '확인 불가'}")
    print("-" * 60)


def test_airplane_mode_toggle(controller):
    """비행기모드 토글 테스트"""
    print("\n" + "-" * 60)
    print("【비행기모드 토글 테스트】")
    print("IP 변경을 위한 비행기모드 토글을 시작합니다.")

    # 이전 IP 확인
    ip_before = controller.get_ip_address()
    print(f"\n현재 IP: {ip_before}")

    input("\n계속하려면 Enter를 누르세요...")

    # 비행기모드 토글
    success = controller.toggle_airplane_mode(duration=3)

    if success:
        print("\n비행기모드 토글 완료! 네트워크 재연결 대기 중...")

        # 네트워크 재연결 대기
        if controller.wait_for_network(timeout=30):
            # 새 IP 확인
            ip_after = controller.get_ip_address()
            print(f"\n이전 IP: {ip_before}")
            print(f"새 IP: {ip_after}")

            if ip_before != ip_after:
                print("\n✅ IP 변경 성공!")
            else:
                print("\n⚠️ IP가 변경되지 않았습니다. (동일한 네트워크에서는 IP가 유지될 수 있음)")
        else:
            print("\n❌ 네트워크 재연결 실패")
    else:
        print("\n❌ 비행기모드 토글 실패")

    print("-" * 60)


def test_screen_control(controller):
    """화면 제어 테스트"""
    print("\n" + "-" * 60)
    print("【화면 제어 테스트】")

    # 화면 켜기
    print("\n1. 화면 켜기...")
    controller.wake_screen()
    time.sleep(1)

    # 홈 버튼
    print("2. 홈 화면으로 이동...")
    controller.press_home()
    time.sleep(1)

    # 화면 중앙 탭
    info = controller.get_device_info()
    center_x = info.get("screen_width", 1080) // 2
    center_y = info.get("screen_height", 1920) // 2

    print(f"3. 화면 중앙 탭: ({center_x}, {center_y})")
    controller.tap(center_x, center_y)
    time.sleep(1)

    # 스크롤 다운
    print("4. 아래로 스크롤...")
    controller.scroll_down()
    time.sleep(1)

    # 스크롤 업
    print("5. 위로 스크롤...")
    controller.scroll_up()
    time.sleep(1)

    print("\n✅ 화면 제어 테스트 완료")
    print("-" * 60)


def test_url_open(controller):
    """URL 열기 테스트"""
    print("\n" + "-" * 60)
    print("【URL 열기 테스트】")

    urls = [
        ("네이버", "https://www.naver.com"),
        ("네이버 쇼핑", "https://shopping.naver.com"),
    ]

    for name, url in urls:
        print(f"\n{name} 열기...")
        controller.open_url(url)
        time.sleep(3)

        # 뒤로가기
        print("뒤로가기...")
        controller.press_back()
        time.sleep(1)

    print("\n✅ URL 열기 테스트 완료")
    print("-" * 60)


def test_text_input(controller):
    """텍스트 입력 테스트"""
    print("\n" + "-" * 60)
    print("【텍스트 입력 테스트】")

    print("\n1. 네이버 열기...")
    controller.open_url("https://m.naver.com")
    time.sleep(3)

    # 검색창 탭 (상단 중앙 근처)
    info = controller.get_device_info()
    search_x = info.get("screen_width", 1080) // 2
    search_y = int(info.get("screen_height", 1920) * 0.1)  # 상단 10% 지점

    print(f"2. 검색창 탭: ({search_x}, {search_y})")
    controller.tap(search_x, search_y)
    time.sleep(1)

    # 텍스트 입력
    test_text = "무선 이어폰"
    print(f"3. 텍스트 입력: '{test_text}'")
    controller.input_text(test_text)
    time.sleep(1)

    # 엔터
    print("4. 검색 실행 (Enter)")
    controller.press_enter()
    time.sleep(2)

    print("\n✅ 텍스트 입력 테스트 완료")
    print("   (검색 결과를 확인하세요)")
    input("\n확인 후 Enter를 누르세요...")

    controller.press_home()
    print("-" * 60)


def auto_test_all(controller):
    """전체 자동 테스트"""
    print("\n" + "=" * 60)
    print("전체 기능 자동 테스트 시작")
    print("=" * 60)

    tests = [
        ("기본 정보", lambda: test_basic_info(controller)),
        ("화면 제어", lambda: test_screen_control(controller)),
        ("URL 열기", lambda: test_url_open(controller)),
        ("스크린샷", lambda: controller.take_screenshot()),
    ]

    for idx, (name, test_func) in enumerate(tests, 1):
        print(f"\n[{idx}/{len(tests)}] {name} 테스트 중...")
        try:
            test_func()
            print(f"✅ {name} 완료")
        except Exception as e:
            print(f"❌ {name} 실패: {e}")

        time.sleep(2)

    print("\n" + "=" * 60)
    print("전체 테스트 완료!")
    print("=" * 60)


def main():
    """메인 함수"""
    print("\n네이버 쇼핑 트래픽 테스트 - ADB 제어 모듈")
    print("\n[초기화 중...]")

    try:
        # ADB 컨트롤러 초기화
        controller = ADBController()

        print("✅ ADB 연결 성공!")

        # 기기 정보 표시
        info = controller.get_device_info()
        print(f"기기: {info.get('manufacturer')} {info.get('model')}")
        print(f"Android: {info.get('android_version')}")
        print(f"화면: {info.get('screen_width')}x{info.get('screen_height')}")

        while True:
            print_menu()
            choice = input("\n선택하세요: ").strip()

            try:
                if choice == "0":
                    print("\n종료합니다.")
                    break

                elif choice == "1":
                    devices = controller.list_devices()
                    print(f"\n연결된 기기: {devices}")

                elif choice == "2":
                    test_basic_info(controller)

                elif choice == "3":
                    ip = controller.get_ip_address()
                    print(f"\nIP 주소: {ip or '확인 불가'}")

                elif choice == "4":
                    print("\n비행기모드 활성화 중...")
                    controller.enable_airplane_mode()

                elif choice == "5":
                    print("\n비행기모드 비활성화 중...")
                    controller.disable_airplane_mode()

                elif choice == "6":
                    test_airplane_mode_toggle(controller)

                elif choice == "7":
                    print("\n네트워크 재연결 대기 중...")
                    controller.wait_for_network()

                elif choice == "8":
                    info = controller.get_device_info()
                    x = info.get("screen_width", 1080) // 2
                    y = info.get("screen_height", 1920) // 2
                    print(f"\n화면 중앙 탭: ({x}, {y})")
                    controller.tap(x, y)

                elif choice == "9":
                    print("\n아래로 스크롤...")
                    controller.scroll_down()

                elif choice == "10":
                    print("\n위로 스크롤...")
                    controller.scroll_up()

                elif choice == "11":
                    test_text_input(controller)

                elif choice == "12":
                    print("\n네이버 열기...")
                    controller.open_url("https://m.naver.com")

                elif choice == "13":
                    print("\n네이버 쇼핑 열기...")
                    controller.open_url("https://mshopping.naver.com")

                elif choice == "14":
                    print("\nChrome 브라우저 실행...")
                    controller.launch_app("com.android.chrome")

                elif choice == "15":
                    print("\n홈 버튼...")
                    controller.press_home()

                elif choice == "16":
                    print("\n뒤로가기...")
                    controller.press_back()

                elif choice == "17":
                    print("\n스크린샷 저장 중...")
                    path = controller.take_screenshot()
                    if path:
                        print(f"저장 완료: {path}")

                elif choice == "18":
                    print("\n화면 켜기...")
                    controller.wake_screen()

                elif choice == "99":
                    auto_test_all(controller)

                else:
                    print("\n잘못된 선택입니다.")

            except Exception as e:
                log.error(f"실행 중 오류: {e}")
                print(f"\n❌ 오류 발생: {e}")

    except Exception as e:
        log.error(f"ADB 초기화 실패: {e}")
        print(f"\n❌ ADB 초기화 실패: {e}")
        print("\n【해결 방법】")
        print("1. USB 디버깅이 활성화되어 있는지 확인")
        print("2. adb devices 명령어로 기기 연결 확인")
        print("3. .env 파일에 ADB_DEVICE_ID 설정 확인")
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n사용자에 의해 중단되었습니다.")
    except Exception as e:
        log.error(f"테스트 실행 중 오류: {e}")
        raise
