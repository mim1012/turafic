"""
순위 체크 모듈 테스트 스크립트

사용법:
  python test_rank_checker.py
"""
from src.ranking.checker import RankChecker
from src.ranking.tracker import RankTracker
from src.utils.logger import log


def test_basic_rank_check():
    """기본 순위 체크 테스트"""
    print("\n" + "=" * 60)
    print("순위 체크 모듈 테스트")
    print("=" * 60)

    # 테스트 데이터 입력 받기
    print("\n[주의] 실제 네이버 쇼핑 상품 정보를 입력하세요.")
    keyword = input("검색 키워드를 입력하세요 (예: 무선 이어폰): ").strip()

    if not keyword:
        keyword = "무선 이어폰"
        print(f"기본값 사용: {keyword}")

    product_id = input("상품 ID를 입력하세요 (URL의 숫자 부분): ").strip()

    if not product_id:
        print("상품 ID가 입력되지 않아 테스트를 종료합니다.")
        print("\n[참고] 상품 ID 찾는 방법:")
        print("1. 네이버 쇼핑에서 상품 검색")
        print("2. 상품 클릭하여 URL 확인")
        print("3. URL에서 숫자 부분 복사")
        print("   예: https://shopping.naver.com/products/12345678")
        print("       → 상품 ID: 12345678")
        return

    max_page = 5  # 테스트는 5페이지만

    # 순위 체크 실행
    print(f"\n검색 시작...")
    print(f"  - 키워드: {keyword}")
    print(f"  - 상품 ID: {product_id}")
    print(f"  - 최대 페이지: {max_page}")
    print()

    checker = RankChecker()
    result = checker.check_product_rank(keyword, product_id, max_page)

    # 결과 출력
    print("\n" + "-" * 60)
    if result:
        print("✅ 상품을 찾았습니다!")
        print(f"\n【순위 정보】")
        print(f"  페이지:     {result['page']}페이지")
        print(f"  위치:       {result['position']}번째")
        print(f"  절대 순위:  {result['absolute_rank']}위")
        print(f"  상품명:     {result['product_name']}")
        print(f"  확인 시각:  {result['checked_at']}")

        # Tracker에 저장 테스트
        print(f"\n순위 추적 데이터 저장 중...")
        tracker = RankTracker(product_id)
        tracker.add_record(result, iteration=1, test_case_id=1, notes="테스트 실행")

        stats = tracker.get_statistics()
        print(f"\n【추적 통계】")
        print(f"  총 기록 수: {stats.get('total_records', 0)}개")
        print(f"  평균 순위: {stats.get('average_rank', 'N/A')}")

    else:
        print(f"❌ 상품을 찾을 수 없습니다.")
        print(f"   {max_page}페이지 이내에 해당 상품이 없습니다.")
        print(f"\n【확인 사항】")
        print(f"  - 키워드가 정확한가요?")
        print(f"  - 상품 ID가 올바른가요?")
        print(f"  - 상품이 {max_page * 20}위 안에 있나요?")

    print("-" * 60)


def test_html_parsing():
    """HTML 파싱 테스트"""
    print("\n" + "=" * 60)
    print("HTML 파싱 테스트 (네이버 쇼핑 선택자 검증)")
    print("=" * 60)

    keyword = input("\n검색 키워드 입력 (예: 아이폰 15): ").strip()
    if not keyword:
        keyword = "아이폰 15"
        print(f"기본값 사용: {keyword}")

    print(f"\n{keyword} 검색 결과 1페이지 파싱 중...")

    checker = RankChecker()
    url = checker.build_search_url(keyword, page=1)

    from src.utils.helpers import safe_request
    response = safe_request(url)

    if response:
        products = checker.parse_products_from_html(response.text, page=1)

        print(f"\n✅ 파싱 완료: {len(products)}개 상품 발견")

        if products:
            print(f"\n【상위 5개 상품】")
            for i, product in enumerate(products[:5], 1):
                print(f"{i}. {product['absolute_rank']}위 - {product['product_name'][:30]}...")
                print(f"   ID: {product['product_id']}")
        else:
            print("⚠️ 상품을 파싱하지 못했습니다.")
            print("네이버 쇼핑 HTML 구조가 변경되었을 수 있습니다.")
            print("src/ranking/checker.py의 선택자를 업데이트해야 합니다.")
    else:
        print("❌ 페이지 요청 실패")


def main():
    """메인 함수"""
    print("\n네이버 쇼핑 순위 체크 모듈 테스트")
    print("\n선택하세요:")
    print("1. 기본 순위 체크 테스트 (상품 ID 필요)")
    print("2. HTML 파싱 테스트 (선택자 검증)")
    print("3. 종료")

    choice = input("\n선택 (1-3): ").strip()

    if choice == "1":
        test_basic_rank_check()
    elif choice == "2":
        test_html_parsing()
    elif choice == "3":
        print("종료합니다.")
    else:
        print("잘못된 선택입니다.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n사용자에 의해 중단되었습니다.")
    except Exception as e:
        log.error(f"테스트 실행 중 오류 발생: {e}")
        raise
