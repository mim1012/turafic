"""
브라우저 지문 프로필 관리

3가지 프로필로 봇 탐지 회피 및 상호작용 효과 측정
"""
import random
from typing import Dict, List
from dataclasses import dataclass


@dataclass
class BrowserFingerprint:
    """브라우저 지문 데이터 클래스"""
    profile_name: str
    canvas_fingerprint: str
    webgl_vendor: str
    webgl_renderer: str
    screen_resolution: str
    color_depth: int
    timezone: str
    platform: str
    hardware_concurrency: int
    device_memory: int
    languages: List[str]
    plugins: List[str]
    user_agent: str
    do_not_track: str
    cookies_enabled: bool


class FingerprintProfiles:
    """브라우저 지문 프로필 관리"""

    # Profile A: 일반 사용자 (중간 사양)
    PROFILE_A = BrowserFingerprint(
        profile_name="일반 사용자",
        canvas_fingerprint="hash_a1b2c3d4e5",
        webgl_vendor="Intel Inc.",
        webgl_renderer="Intel Iris OpenGL Engine",
        screen_resolution="1920x1080",
        color_depth=24,
        timezone="Asia/Seoul",
        platform="Win32",
        hardware_concurrency=8,
        device_memory=8,
        languages=["ko-KR", "ko", "en-US"],
        plugins=[
            "Chrome PDF Plugin",
            "Chrome PDF Viewer",
            "Native Client"
        ],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        do_not_track="1",
        cookies_enabled=True
    )

    # Profile B: 고사양 사용자 (게이머/전문가)
    PROFILE_B = BrowserFingerprint(
        profile_name="고사양 사용자",
        canvas_fingerprint="hash_f6g7h8i9j0",
        webgl_vendor="NVIDIA Corporation",
        webgl_renderer="NVIDIA GeForce RTX 3080/PCIe/SSE2",
        screen_resolution="2560x1440",
        color_depth=32,
        timezone="Asia/Seoul",
        platform="Win32",
        hardware_concurrency=16,
        device_memory=32,
        languages=["ko-KR", "en-US"],
        plugins=[
            "Chrome PDF Plugin",
            "Chrome PDF Viewer",
            "Native Client",
            "Widevine Content Decryption Module"
        ],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        do_not_track="null",  # 고급 사용자는 DNT 비활성화
        cookies_enabled=True
    )

    # Profile C: 모바일 사용자 (스마트폰)
    PROFILE_C = BrowserFingerprint(
        profile_name="모바일 사용자",
        canvas_fingerprint="hash_k1l2m3n4o5",
        webgl_vendor="ARM",
        webgl_renderer="Mali-G78",
        screen_resolution="1080x2400",
        color_depth=24,
        timezone="Asia/Seoul",
        platform="Linux aarch64",
        hardware_concurrency=8,
        device_memory=8,
        languages=["ko-KR", "ko"],
        plugins=[],  # 모바일은 플러그인 없음
        user_agent="Mozilla/5.0 (Linux; Android 12; SM-G991N) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        do_not_track="1",
        cookies_enabled=True
    )

    @classmethod
    def get_profile(cls, profile_name: str) -> BrowserFingerprint:
        """프로필 이름으로 지문 가져오기"""
        profiles = {
            "A": cls.PROFILE_A,
            "B": cls.PROFILE_B,
            "C": cls.PROFILE_C,
        }
        return profiles.get(profile_name.upper(), cls.PROFILE_A)

    @classmethod
    def get_all_profiles(cls) -> List[BrowserFingerprint]:
        """모든 프로필 반환"""
        return [cls.PROFILE_A, cls.PROFILE_B, cls.PROFILE_C]

    @classmethod
    def get_random_profile(cls) -> BrowserFingerprint:
        """랜덤 프로필 선택"""
        return random.choice(cls.get_all_profiles())


class FingerprintInjector:
    """브라우저 지문 주입기 (HTTP 헤더 및 JavaScript 주입)"""

    @staticmethod
    def generate_http_headers(fingerprint: BrowserFingerprint) -> Dict[str, str]:
        """HTTP 헤더 생성"""
        headers = {
            'User-Agent': fingerprint.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': ','.join(fingerprint.languages) + ';q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': fingerprint.do_not_track,
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

        # Profile별 특수 헤더
        if fingerprint.profile_name == "모바일 사용자":
            headers['Sec-Ch-Ua-Mobile'] = '?1'
            headers['Sec-Ch-Ua-Platform'] = '"Android"'
        else:
            headers['Sec-Ch-Ua-Mobile'] = '?0'
            headers['Sec-Ch-Ua-Platform'] = '"Windows"'

        return headers

    @staticmethod
    def generate_javascript_injection(fingerprint: BrowserFingerprint) -> str:
        """JavaScript 주입 코드 생성 (Selenium/Playwright용)"""
        js_code = f"""
        // Canvas Fingerprint Override
        (function() {{
            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function(type) {{
                const canvas = this;
                const context = canvas.getContext('2d');

                // 노이즈 주입 (미세한 픽셀 변화)
                const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                for (let i = 0; i < imageData.data.length; i += 4) {{
                    imageData.data[i] += Math.floor(Math.random() * 3) - 1; // R
                }}
                context.putImageData(imageData, 0, 0);

                return originalToDataURL.call(this, type);
            }};
        }})();

        // WebGL Fingerprint Override
        Object.defineProperty(WebGLRenderingContext.prototype, 'getParameter', {{
            value: function(parameter) {{
                if (parameter === 37445) {{ // UNMASKED_VENDOR_WEBGL
                    return "{fingerprint.webgl_vendor}";
                }}
                if (parameter === 37446) {{ // UNMASKED_RENDERER_WEBGL
                    return "{fingerprint.webgl_renderer}";
                }}
                return this.constructor.prototype.getParameter.call(this, parameter);
            }}
        }});

        // Screen Resolution
        Object.defineProperty(window.screen, 'width', {{
            get: () => {fingerprint.screen_resolution.split('x')[0]}
        }});
        Object.defineProperty(window.screen, 'height', {{
            get: () => {fingerprint.screen_resolution.split('x')[1]}
        }});
        Object.defineProperty(window.screen, 'colorDepth', {{
            get: () => {fingerprint.color_depth}
        }});

        // Hardware Concurrency
        Object.defineProperty(navigator, 'hardwareConcurrency', {{
            get: () => {fingerprint.hardware_concurrency}
        }});

        // Device Memory
        Object.defineProperty(navigator, 'deviceMemory', {{
            get: () => {fingerprint.device_memory}
        }});

        // Languages
        Object.defineProperty(navigator, 'languages', {{
            get: () => {fingerprint.languages}
        }});

        // Platform
        Object.defineProperty(navigator, 'platform', {{
            get: () => "{fingerprint.platform}"
        }});

        // Plugins
        Object.defineProperty(navigator, 'plugins', {{
            get: () => {{
                const pluginArray = {fingerprint.plugins};
                return pluginArray.map((name, i) => ({{
                    name: name,
                    filename: name.toLowerCase().replace(/\\s+/g, '-') + '.so',
                    description: name,
                    length: 1
                }}));
            }}
        }});

        console.log('[Fingerprint] Profile "{fingerprint.profile_name}" injected');
        }})();
        """
        return js_code

    @staticmethod
    def inject_to_selenium(driver, fingerprint: BrowserFingerprint):
        """Selenium WebDriver에 지문 주입"""
        js_code = FingerprintInjector.generate_javascript_injection(fingerprint)
        driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
            'source': js_code
        })

    @staticmethod
    def inject_to_playwright(page, fingerprint: BrowserFingerprint):
        """Playwright Page에 지문 주입"""
        js_code = FingerprintInjector.generate_javascript_injection(fingerprint)
        page.add_init_script(js_code)

    @staticmethod
    def inject_to_appium(driver, fingerprint: BrowserFingerprint):
        """Appium WebDriver에 지문 주입 (제한적)"""
        # Appium은 JavaScript 주입이 제한적이므로 User-Agent만 변경
        # 실제 기기 특성을 사용하는 것이 더 효과적
        pass


class FingerprintValidator:
    """브라우저 지문 검증기"""

    @staticmethod
    def validate_fingerprint(driver) -> Dict[str, str]:
        """현재 브라우저의 지문 정보 확인"""
        validation_script = """
        return {
            canvas: (() => {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillText('Test', 2, 2);
                return canvas.toDataURL();
            })(),
            webgl: (() => {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl');
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                return {
                    vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                    renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
                };
            })(),
            screen: {
                width: window.screen.width,
                height: window.screen.height,
                colorDepth: window.screen.colorDepth
            },
            navigator: {
                platform: navigator.platform,
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory,
                languages: navigator.languages
            }
        };
        """

        try:
            result = driver.execute_script(validation_script)
            return result
        except Exception as e:
            return {"error": str(e)}


# 편의 함수
def get_profile_for_category(category: str) -> BrowserFingerprint:
    """카테고리별 추천 프로필"""
    recommendations = {
        "전자기기": FingerprintProfiles.PROFILE_B,  # 고사양 사용자
        "패션의류": FingerprintProfiles.PROFILE_C,  # 모바일 사용자
        "식품": FingerprintProfiles.PROFILE_A,      # 일반 사용자
        "뷰티": FingerprintProfiles.PROFILE_C,      # 모바일 사용자
    }
    return recommendations.get(category, FingerprintProfiles.PROFILE_A)


# 사용 예시
if __name__ == "__main__":
    # Profile A 가져오기
    profile_a = FingerprintProfiles.get_profile("A")
    print(f"Profile: {profile_a.profile_name}")
    print(f"WebGL: {profile_a.webgl_renderer}")
    print(f"Resolution: {profile_a.screen_resolution}")

    # HTTP 헤더 생성
    headers = FingerprintInjector.generate_http_headers(profile_a)
    print(f"\nUser-Agent: {headers['User-Agent']}")

    # JavaScript 코드 생성
    js_code = FingerprintInjector.generate_javascript_injection(profile_a)
    print(f"\nJS Code length: {len(js_code)} characters")

    # 카테고리별 추천
    print("\n카테고리별 추천 프로필:")
    for cat in ["전자기기", "패션의류", "식품", "뷰티"]:
        recommended = get_profile_for_category(cat)
        print(f"  {cat}: {recommended.profile_name}")
