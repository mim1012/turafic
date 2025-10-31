"""
Playwright로 네이버 쇼핑 유입 경로 탐색

목적: 다양한 유입 경로를 직접 확인하여 특이 케이스 발굴
"""
import asyncio
from playwright.async_api import async_playwright
import time


async def explore_naver_shopping_paths():
    """네이버 쇼핑 다양한 유입 경로 탐색"""

    async with async_playwright() as p:
        # 브라우저 실행 (헤드리스 OFF - 직접 보기 위해)
        browser = await p.chromium.launch(headless=False, slow_mo=1000)
        context = await browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        page = await context.new_page()

        print("\n" + "="*80)
        print("네이버 쇼핑 유입 경로 탐색 시작")
        print("="*80)

        # =====================================================================
        # 경로 1: 네이버 메인 → 통합검색 → 쇼핑탭
        # =====================================================================
        print("\n【경로 1】 네이버 메인 → 통합검색 → 쇼핑탭")
        await page.goto('https://www.naver.com')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 가장 일반적인 경로")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 2: 네이버 쇼핑 직접 접속
        # =====================================================================
        print("\n【경로 2】 네이버 쇼핑 직접 접속")
        await page.goto('https://shopping.naver.com')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 쇼핑 의도 명확한 사용자")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 3: 네이버 쇼핑 > 카테고리 탐색
        # =====================================================================
        print("\n【경로 3】 네이버 쇼핑 > 카테고리 탐색")
        await page.goto('https://shopping.naver.com/home')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 카테고리 브라우징 → 상품 발견")

        # 카테고리 메뉴 확인
        try:
            categories = await page.locator('a[href*="category"]').all()
            print(f"  - 발견된 카테고리 수: {len(categories)}")
            if categories:
                first_cat = categories[0]
                cat_text = await first_cat.inner_text()
                print(f"  - 첫 번째 카테고리: {cat_text}")
        except:
            print("  - 카테고리 요소 찾기 실패")

        await asyncio.sleep(2)

        # =====================================================================
        # 경로 4: 네이버 쇼핑 > 랭킹/베스트
        # =====================================================================
        print("\n【경로 4】 네이버 쇼핑 > 랭킹/베스트")
        await page.goto('https://shopping.naver.com/best/home')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 인기 상품 탐색 → 트렌드 민감")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 5: 네이버 쇼핑 > 브랜드관
        # =====================================================================
        print("\n【경로 5】 네이버 쇼핑 > 브랜드관")
        await page.goto('https://shopping.naver.com/brands/store/home')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 브랜드 충성도 높은 사용자")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 6: 네이버 쇼핑 > 타임딜/특가
        # =====================================================================
        print("\n【경로 6】 네이버 쇼핑 > 타임딜/특가")
        await page.goto('https://shopping.naver.com/living/homedeal')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 가격 민감 구매자, 즉시 구매 가능성")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 7: 네이버 쇼핑 > 쿠폰/혜택
        # =====================================================================
        print("\n【경로 7】 네이버 쇼핑 > 쿠폰/혜택")
        await page.goto('https://shopping.naver.com/benefits/coupons')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 할인 적극 활용, 구매 의도 강함")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 8: 네이버 쇼핑 > 스타일윈도우 (패션)
        # =====================================================================
        print("\n【경로 8】 네이버 쇼핑 > 스타일윈도우")
        await page.goto('https://shopping.naver.com/stylewindow/home')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 패션 트렌드 관심, 스타일링 중시")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 9: 네이버 쇼핑 > 리뷰 많은 상품
        # =====================================================================
        print("\n【경로 9】 네이버 쇼핑 > 리뷰 많은 상품")
        await page.goto('https://shopping.naver.com/best/review')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 검증된 상품 선호, 신중한 구매자")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 10: 네이버 쇼핑 > 신상품
        # =====================================================================
        print("\n【경로 10】 네이버 쇼핑 > 신상품")
        await page.goto('https://shopping.naver.com/best/new')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 얼리어답터, 신제품 관심")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 11: 모바일 네이버 쇼핑
        # =====================================================================
        print("\n【경로 11】 모바일 네이버 쇼핑")
        # 모바일 User-Agent로 변경
        mobile_context = await browser.new_context(
            viewport={'width': 375, 'height': 812},  # iPhone X
            user_agent='Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
        )
        mobile_page = await mobile_context.new_page()
        await mobile_page.goto('https://m.shopping.naver.com')
        await mobile_page.wait_for_load_state('networkidle')
        print("  - URL:", mobile_page.url)
        print("  - 특징: 모바일 전용 UI, 즉시 구매 경향")
        await asyncio.sleep(2)
        await mobile_context.close()

        # =====================================================================
        # 경로 12: 네이버 페이 포인트/혜택에서 유입
        # =====================================================================
        print("\n【경로 12】 네이버 페이 포인트/혜택")
        await page.goto('https://shopping.naver.com/benefits/home')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 포인트 적립/사용 관심, 충성 고객")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 13: 외부 검색엔진 (구글) 시뮬레이션
        # =====================================================================
        print("\n【경로 13】 외부 검색엔진 (구글) 유입 시뮬레이션")
        # Referer 헤더 설정
        await page.set_extra_http_headers({
            'Referer': 'https://www.google.com/search?q=무선+이어폰'
        })
        await page.goto('https://shopping.naver.com')
        print("  - Referer: Google Search")
        print("  - 특징: 외부 검색 유입, 높은 구매 의도")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 14: 네이버 블로그 리뷰에서 유입
        # =====================================================================
        print("\n【경로 14】 네이버 블로그 리뷰 유입 시뮬레이션")
        await page.set_extra_http_headers({
            'Referer': 'https://blog.naver.com/sample-review'
        })
        # UTM 파라미터 추가
        test_url = 'https://shopping.naver.com?utm_source=blog&utm_medium=review&utm_campaign=product'
        await page.goto(test_url)
        print("  - Referer: Naver Blog")
        print("  - UTM: blog/review/product")
        print("  - 특징: 리뷰 기반 유입, 신뢰도 높음")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 15: 네이버 카페 정보글에서 유입
        # =====================================================================
        print("\n【경로 15】 네이버 카페 유입 시뮬레이션")
        await page.set_extra_http_headers({
            'Referer': 'https://cafe.naver.com/sample-cafe'
        })
        test_url = 'https://shopping.naver.com?utm_source=cafe&utm_medium=post'
        await page.goto(test_url)
        print("  - Referer: Naver Cafe")
        print("  - 특징: 커뮤니티 추천 유입, 바이럴 효과")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 16: 이메일/뉴스레터 유입
        # =====================================================================
        print("\n【경로 16】 이메일/뉴스레터 유입 시뮬레이션")
        test_url = 'https://shopping.naver.com?utm_source=email&utm_medium=newsletter&utm_campaign=weekly'
        await page.goto(test_url)
        print("  - UTM: email/newsletter/weekly")
        print("  - 특징: 구독자, 정기 구매 가능성")
        await asyncio.sleep(2)

        # =====================================================================
        # 경로 17: 네이버 앱 내부 광고/배너
        # =====================================================================
        print("\n【경로 17】 네이버 앱 광고/배너 유입 시뮬레이션")
        test_url = 'https://shopping.naver.com?utm_source=naverapp&utm_medium=banner&utm_campaign=mainbanner'
        await page.goto(test_url)
        print("  - UTM: naverapp/banner")
        print("  - 특징: 앱 사용자, 충성도 높음")
        await asyncio.sleep(2)

        # =====================================================================
        # 요약 출력
        # =====================================================================
        print("\n" + "="*80)
        print("탐색 완료!")
        print("="*80)
        print("\n발견된 특이 유입 경로:")
        print("  1. 카테고리 탐색 → 상품 발견")
        print("  2. 랭킹/베스트 → 인기 상품")
        print("  3. 브랜드관 → 브랜드 충성")
        print("  4. 타임딜/특가 → 즉시 구매")
        print("  5. 쿠폰/혜택 → 할인 활용")
        print("  6. 스타일윈도우 → 패션 트렌드")
        print("  7. 리뷰 많은 상품 → 검증된 상품")
        print("  8. 신상품 → 얼리어답터")
        print("  9. 네이버 페이 혜택 → 포인트 사용")
        print(" 10. 구글 검색 유입 → 외부 검색")
        print(" 11. 블로그 리뷰 유입 → 신뢰도")
        print(" 12. 카페 추천 유입 → 커뮤니티")
        print(" 13. 이메일/뉴스레터 → 구독자")
        print(" 14. 네이버 앱 배너 → 앱 사용자")

        print("\n브라우저를 10초 후 종료합니다...")
        await asyncio.sleep(10)

        await browser.close()


async def explore_product_discovery_paths():
    """상품 발견 경로 탐색"""

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False, slow_mo=1000)
        page = await browser.new_page()

        print("\n" + "="*80)
        print("상품 발견 경로 세부 탐색")
        print("="*80)

        # =====================================================================
        # 특이 케이스 1: 가격 비교 사이트에서 유입
        # =====================================================================
        print("\n【특이 케이스 1】 가격 비교 사이트 유입")
        await page.set_extra_http_headers({
            'Referer': 'https://www.danawa.com'
        })
        await page.goto('https://shopping.naver.com')
        print("  - 특징: 가격 중심 비교, 최저가 찾는 사용자")
        await asyncio.sleep(2)

        # =====================================================================
        # 특이 케이스 2: 네이버 통합검색 > 이미지 검색 > 쇼핑
        # =====================================================================
        print("\n【특이 케이스 2】 이미지 검색에서 쇼핑 유입")
        await page.goto('https://search.shopping.naver.com/image/search/all')
        await page.wait_for_load_state('networkidle')
        print("  - URL:", page.url)
        print("  - 특징: 시각적 탐색, 디자인 중시")
        await asyncio.sleep(2)

        # =====================================================================
        # 특이 케이스 3: 네이버 페이 > 장바구니 > 쇼핑 계속
        # =====================================================================
        print("\n【특이 케이스 3】 네이버 페이 장바구니에서 재접근")
        await page.goto('https://shopping.naver.com/cart')
        await page.wait_for_load_state('networkidle')
        print("  - 특징: 장바구니 있음 → 추가 상품 탐색")
        await asyncio.sleep(2)

        # =====================================================================
        # 특이 케이스 4: 구매 내역 > 재구매 > 유사 상품
        # =====================================================================
        print("\n【특이 케이스 4】 주문 내역에서 유사 상품 탐색")
        await page.goto('https://shopping.naver.com/my/orders')
        await page.wait_for_load_state('networkidle')
        print("  - 특징: 재구매 의도, 충성 고객")
        await asyncio.sleep(2)

        # =====================================================================
        # 특이 케이스 5: 찜한 상품 목록에서 접근
        # =====================================================================
        print("\n【특이 케이스 5】 찜한 상품 목록")
        await page.goto('https://shopping.naver.com/my/interests')
        await page.wait_for_load_state('networkidle')
        print("  - 특징: 관심 상품, 가격 비교 중")
        await asyncio.sleep(2)

        # =====================================================================
        # 특이 케이스 6: 최근 본 상품에서 재방문
        # =====================================================================
        print("\n【특이 케이스 6】 최근 본 상품에서 재방문")
        await page.goto('https://shopping.naver.com/my/recent')
        await page.wait_for_load_state('networkidle')
        print("  - 특징: 재고민 중, 구매 망설임")
        await asyncio.sleep(2)

        print("\n브라우저를 10초 후 종료합니다...")
        await asyncio.sleep(10)

        await browser.close()


async def main():
    """메인 함수"""
    print("""
    ╔════════════════════════════════════════════════════════════════════╗
    ║  네이버 쇼핑 유입 경로 탐색 도구                                    ║
    ║  Playwright를 사용하여 다양한 유입 경로 확인                        ║
    ╚════════════════════════════════════════════════════════════════════╝
    """)

    print("\n실행할 탐색을 선택하세요:")
    print("1. 기본 유입 경로 탐색 (17개)")
    print("2. 상품 발견 경로 세부 탐색 (6개)")
    print("3. 전체 탐색 (1+2)")

    choice = input("\n선택 (1-3): ").strip()

    if choice == "1":
        await explore_naver_shopping_paths()
    elif choice == "2":
        await explore_product_discovery_paths()
    elif choice == "3":
        await explore_naver_shopping_paths()
        await explore_product_discovery_paths()
    else:
        print("잘못된 선택입니다.")


if __name__ == "__main__":
    print("\n[주의] Playwright가 설치되어 있어야 합니다.")
    print("설치: pip install playwright && playwright install chromium\n")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n사용자에 의해 중단되었습니다.")
    except Exception as e:
        print(f"\n오류 발생: {e}")
