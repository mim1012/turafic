"""
순위 체크 정확도 검증 단위 테스트

이 테스트는 실제 네이버 쇼핑 검색 결과와 RankChecker의 결과를 비교하여
순위 체크의 정확도를 검증합니다.

사용법:
  python test_rank_accuracy.py

테스트 방법:
  1. 네이버 쇼핑에서 수동으로 순위 확인
  2. RankChecker로 자동 순위 체크
  3. 두 결과 비교 (±2위 이내면 정확)
"""
import sys
from typing import Dict, List, Tuple
from src.ranking.checker import RankChecker
from src.utils.logger import log


class RankAccuracyTester:
    """순위 체크 정확도 테스터"""
    
    def __init__(self):
        self.checker = RankChecker()
        self.test_cases: List[Dict] = []
        self.results: List[Dict] = []
    
    def add_test_case(
        self,
        keyword: str,
        product_id: str,
        expected_rank: int,
        product_name: str = ""
    ):
        """
        테스트 케이스 추가
        
        Args:
            keyword: 검색 키워드
            product_id: 상품 ID
            expected_rank: 예상 순위 (수동 확인)
            product_name: 상품명 (선택)
        """
        self.test_cases.append({
            "keyword": keyword,
            "product_id": product_id,
            "expected_rank": expected_rank,
            "product_name": product_name
        })
    
    def run_tests(self, tolerance: int = 2) -> Dict:
        """
        모든 테스트 케이스 실행
        
        Args:
            tolerance: 허용 오차 (±N위)
        
        Returns:
            테스트 결과 요약
        """
        print("\n" + "=" * 80)
        print("순위 체크 정확도 검증 테스트")
        print("=" * 80)
        print(f"\n총 테스트 케이스: {len(self.test_cases)}개")
        print(f"허용 오차: ±{tolerance}위\n")
        
        passed = 0
        failed = 0
        not_found = 0
        
        for i, test_case in enumerate(self.test_cases, 1):
            print(f"\n[테스트 {i}/{len(self.test_cases)}]")
            print(f"키워드: {test_case['keyword']}")
            print(f"상품 ID: {test_case['product_id']}")
            print(f"예상 순위: {test_case['expected_rank']}위")
            
            # 순위 체크 실행
            max_page = (test_case['expected_rank'] // 20) + 2  # 예상 페이지 + 여유
            result = self.checker.check_product_rank(
                test_case['keyword'],
                test_case['product_id'],
                max_page=max_page
            )
            
            if result:
                actual_rank = result['absolute_rank']
                difference = abs(actual_rank - test_case['expected_rank'])
                
                # 정확도 판정
                if difference <= tolerance:
                    status = "✅ PASS"
                    passed += 1
                else:
                    status = "❌ FAIL"
                    failed += 1
                
                print(f"실제 순위: {actual_rank}위")
                print(f"오차: {difference}위")
                print(f"결과: {status}")
                
                # 결과 저장
                self.results.append({
                    "test_case": test_case,
                    "actual_rank": actual_rank,
                    "difference": difference,
                    "passed": difference <= tolerance
                })
            else:
                print(f"실제 순위: 찾을 수 없음")
                print(f"결과: ⚠️ NOT FOUND")
                not_found += 1
                
                self.results.append({
                    "test_case": test_case,
                    "actual_rank": None,
                    "difference": None,
                    "passed": False
                })
        
        # 결과 요약
        total = len(self.test_cases)
        accuracy = (passed / total * 100) if total > 0 else 0
        
        summary = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "not_found": not_found,
            "accuracy": accuracy
        }
        
        self._print_summary(summary)
        return summary
    
    def _print_summary(self, summary: Dict):
        """결과 요약 출력"""
        print("\n" + "=" * 80)
        print("테스트 결과 요약")
        print("=" * 80)
        print(f"\n총 테스트: {summary['total']}개")
        print(f"✅ 통과: {summary['passed']}개")
        print(f"❌ 실패: {summary['failed']}개")
        print(f"⚠️ 찾을 수 없음: {summary['not_found']}개")
        print(f"\n정확도: {summary['accuracy']:.1f}%")
        
        if summary['accuracy'] >= 90:
            print("\n🎉 매우 정확합니다!")
        elif summary['accuracy'] >= 70:
            print("\n👍 양호합니다.")
        elif summary['accuracy'] >= 50:
            print("\n⚠️ 개선이 필요합니다.")
        else:
            print("\n❌ 순위 체크 로직을 점검해야 합니다.")
    
    def export_results(self, filename: str = "rank_accuracy_results.txt"):
        """결과를 파일로 저장"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("순위 체크 정확도 검증 결과\n")
            f.write("=" * 80 + "\n\n")
            
            for i, result in enumerate(self.results, 1):
                tc = result['test_case']
                f.write(f"[테스트 {i}]\n")
                f.write(f"키워드: {tc['keyword']}\n")
                f.write(f"상품 ID: {tc['product_id']}\n")
                f.write(f"예상 순위: {tc['expected_rank']}위\n")
                
                if result['actual_rank']:
                    f.write(f"실제 순위: {result['actual_rank']}위\n")
                    f.write(f"오차: {result['difference']}위\n")
                    f.write(f"결과: {'PASS' if result['passed'] else 'FAIL'}\n")
                else:
                    f.write(f"실제 순위: 찾을 수 없음\n")
                    f.write(f"결과: NOT FOUND\n")
                
                f.write("\n")
        
        print(f"\n결과가 {filename}에 저장되었습니다.")


def create_sample_test_cases() -> RankAccuracyTester:
    """
    샘플 테스트 케이스 생성
    
    사용자는 이 함수를 수정하여 실제 테스트 케이스를 추가해야 합니다.
    """
    tester = RankAccuracyTester()
    
    print("\n" + "=" * 80)
    print("테스트 케이스 입력")
    print("=" * 80)
    print("\n[주의] 먼저 네이버 쇼핑에서 수동으로 순위를 확인한 후 입력하세요.")
    print("\n테스트 케이스 입력 방법:")
    print("1. 네이버 쇼핑에서 키워드 검색")
    print("2. 광고를 제외하고 실제 순위 확인")
    print("3. 상품 클릭하여 URL에서 상품 ID 확인")
    print("4. 아래에 정보 입력\n")
    
    # 테스트 케이스 입력
    while True:
        print("-" * 80)
        keyword = input("\n검색 키워드 (종료하려면 엔터): ").strip()
        if not keyword:
            break
        
        product_id = input("상품 ID: ").strip()
        if not product_id:
            print("상품 ID를 입력해야 합니다.")
            continue
        
        try:
            expected_rank = int(input("예상 순위 (수동 확인): ").strip())
        except ValueError:
            print("순위는 숫자로 입력해야 합니다.")
            continue
        
        product_name = input("상품명 (선택, 엔터 스킵): ").strip()
        
        tester.add_test_case(keyword, product_id, expected_rank, product_name)
        print(f"✅ 테스트 케이스 추가됨 (총 {len(tester.test_cases)}개)")
    
    return tester


def run_predefined_tests():
    """
    미리 정의된 테스트 케이스 실행
    
    사용자는 이 함수에 실제 테스트 케이스를 추가해야 합니다.
    """
    tester = RankAccuracyTester()
    
    # 예시 테스트 케이스 (실제 데이터로 교체 필요)
    # tester.add_test_case(
    #     keyword="삼성 갤럭시 S24",
    #     product_id="12345678",
    #     expected_rank=15,
    #     product_name="삼성 갤럭시 S24 울트라"
    # )
    
    print("\n⚠️ 미리 정의된 테스트 케이스가 없습니다.")
    print("run_predefined_tests() 함수에 테스트 케이스를 추가하세요.\n")
    print("예시:")
    print('tester.add_test_case(')
    print('    keyword="삼성 갤럭시 S24",')
    print('    product_id="12345678",')
    print('    expected_rank=15,')
    print('    product_name="삼성 갤럭시 S24 울트라"')
    print(')')
    
    return None


def compare_with_manual_check():
    """
    수동 확인과 자동 체크 비교
    
    실시간으로 수동 확인 → 자동 체크 → 비교
    """
    print("\n" + "=" * 80)
    print("수동 확인 vs 자동 체크 비교")
    print("=" * 80)
    
    keyword = input("\n검색 키워드: ").strip()
    if not keyword:
        print("키워드를 입력해야 합니다.")
        return
    
    print(f"\n1단계: 네이버 쇼핑에서 '{keyword}' 검색")
    print("https://shopping.naver.com/search/all?query=" + keyword)
    print("\n광고를 제외하고 순위를 확인하세요.")
    print("(광고는 '광고' 표시가 있거나 배경색이 다릅니다)")
    
    input("\n확인했으면 엔터를 누르세요...")
    
    product_id = input("\n상품 ID: ").strip()
    if not product_id:
        print("상품 ID를 입력해야 합니다.")
        return
    
    try:
        manual_rank = int(input("수동 확인한 순위: ").strip())
    except ValueError:
        print("순위는 숫자로 입력해야 합니다.")
        return
    
    print(f"\n2단계: 자동 순위 체크 실행 중...")
    
    checker = RankChecker()
    max_page = (manual_rank // 20) + 2
    result = checker.check_product_rank(keyword, product_id, max_page=max_page)
    
    print("\n" + "=" * 80)
    print("비교 결과")
    print("=" * 80)
    
    if result:
        auto_rank = result['absolute_rank']
        difference = abs(auto_rank - manual_rank)
        
        print(f"\n수동 확인 순위: {manual_rank}위")
        print(f"자동 체크 순위: {auto_rank}위")
        print(f"오차: {difference}위")
        
        if difference == 0:
            print("\n✅ 완벽하게 일치합니다!")
        elif difference <= 2:
            print("\n✅ 매우 정확합니다! (±2위 이내)")
        elif difference <= 5:
            print("\n⚠️ 약간의 오차가 있습니다. (±5위 이내)")
        else:
            print("\n❌ 오차가 큽니다. 순위 체크 로직을 점검하세요.")
            print("\n가능한 원인:")
            print("- 광고 필터링 오류")
            print("- HTML 선택자 변경")
            print("- 네이버 쇼핑 구조 변경")
    else:
        print(f"\n❌ 자동 체크 실패: 상품을 찾을 수 없습니다.")
        print(f"   {max_page}페이지 이내에 해당 상품이 없습니다.")


def main():
    """메인 함수"""
    print("\n네이버 쇼핑 순위 체크 정확도 검증")
    print("\n테스트 모드를 선택하세요:")
    print("1. 수동 확인 vs 자동 체크 비교 (1개 상품)")
    print("2. 여러 테스트 케이스 실행 (대화형 입력)")
    print("3. 미리 정의된 테스트 케이스 실행")
    print("4. 종료")
    
    choice = input("\n선택 (1-4): ").strip()
    
    if choice == "1":
        compare_with_manual_check()
    
    elif choice == "2":
        tester = create_sample_test_cases()
        if len(tester.test_cases) > 0:
            summary = tester.run_tests(tolerance=2)
            
            export = input("\n결과를 파일로 저장하시겠습니까? (y/n): ").strip().lower()
            if export == 'y':
                tester.export_results()
        else:
            print("\n테스트 케이스가 없습니다.")
    
    elif choice == "3":
        result = run_predefined_tests()
        if result:
            result.run_tests(tolerance=2)
    
    elif choice == "4":
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
