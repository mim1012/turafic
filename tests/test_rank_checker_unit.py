"""
순위 체크 모듈 단위 테스트 (pytest)

실행 방법:
  pytest tests/test_rank_checker_unit.py -v
  pytest tests/test_rank_checker_unit.py::test_광고_필터링 -v
"""
import pytest
from unittest.mock import Mock, patch
from bs4 import BeautifulSoup
from src.ranking.checker import RankChecker


class TestRankChecker:
    """RankChecker 클래스 단위 테스트"""
    
    @pytest.fixture
    def checker(self):
        """RankChecker 인스턴스 생성"""
        return RankChecker()
    
    def test_검색_URL_생성(self, checker):
        """검색 URL이 올바르게 생성되는지 테스트"""
        url = checker.build_search_url("삼성 갤럭시", page=1)
        
        assert "shopping.naver.com" in url
        assert "query=%EC%82%BC%EC%84%B1" in url  # URL 인코딩된 "삼성"
        assert "pagingIndex=1" in url
        assert "pagingSize=20" in url
    
    def test_검색_URL_페이지_변경(self, checker):
        """페이지 번호가 올바르게 반영되는지 테스트"""
        url_page1 = checker.build_search_url("아이폰", page=1)
        url_page3 = checker.build_search_url("아이폰", page=3)
        
        assert "pagingIndex=1" in url_page1
        assert "pagingIndex=3" in url_page3
    
    def test_상품_ID_추출(self, checker):
        """URL에서 상품 ID가 올바르게 추출되는지 테스트"""
        test_urls = [
            ("https://shopping.naver.com/products/12345678", "12345678"),
            ("/products/87654321", "87654321"),
            ("https://shopping.naver.com/window-products/99999999", "99999999"),
            ("/window-products/11111111", "11111111"),
        ]
        
        for url, expected_id in test_urls:
            product_id = checker._extract_product_id(url)
            assert product_id == expected_id, f"URL {url}에서 ID 추출 실패"
    
    def test_광고_필터링_텍스트(self, checker):
        """'광고' 텍스트가 있는 요소를 광고로 감지하는지 테스트"""
        html = """
        <div class="product_item">
            <span class="ad_badge">광고</span>
            <a href="/products/12345678">상품명</a>
        </div>
        """
        soup = BeautifulSoup(html, 'lxml')
        element = soup.select_one("div.product_item")
        
        is_ad = checker._is_advertisement(element)
        assert is_ad == True, "광고 텍스트를 감지하지 못함"
    
    def test_광고_필터링_클래스(self, checker):
        """광고 관련 CSS 클래스를 감지하는지 테스트"""
        html = """
        <div class="product_item powerlink">
            <a href="/products/12345678">상품명</a>
        </div>
        """
        soup = BeautifulSoup(html, 'lxml')
        element = soup.select_one("div.product_item")
        
        is_ad = checker._is_advertisement(element)
        assert is_ad == True, "광고 클래스를 감지하지 못함"
    
    def test_광고_필터링_data_속성(self, checker):
        """data-ad 속성을 감지하는지 테스트"""
        html = """
        <div class="product_item" data-ad="true">
            <a href="/products/12345678">상품명</a>
        </div>
        """
        soup = BeautifulSoup(html, 'lxml')
        element = soup.select_one("div.product_item")
        
        is_ad = checker._is_advertisement(element)
        assert is_ad == True, "data-ad 속성을 감지하지 못함"
    
    def test_일반_상품_감지(self, checker):
        """광고가 아닌 일반 상품을 올바르게 감지하는지 테스트"""
        html = """
        <div class="product_item">
            <a href="/products/12345678">일반 상품</a>
        </div>
        """
        soup = BeautifulSoup(html, 'lxml')
        element = soup.select_one("div.product_item")
        
        is_ad = checker._is_advertisement(element)
        assert is_ad == False, "일반 상품을 광고로 잘못 감지함"
    
    def test_순위_계산(self, checker):
        """페이지와 위치로 절대 순위가 올바르게 계산되는지 테스트"""
        from src.utils.helpers import calculate_rank
        
        test_cases = [
            (1, 1, 1),    # 1페이지 1번째 → 1위
            (1, 20, 20),  # 1페이지 20번째 → 20위
            (2, 1, 21),   # 2페이지 1번째 → 21위
            (2, 10, 30),  # 2페이지 10번째 → 30위
            (5, 15, 95),  # 5페이지 15번째 → 95위
        ]
        
        for page, position, expected_rank in test_cases:
            rank = calculate_rank(page, position, items_per_page=20)
            assert rank == expected_rank, f"페이지 {page}, 위치 {position}의 순위 계산 오류"
    
    @patch('src.ranking.checker.safe_request')
    def test_상품_찾기_성공(self, mock_request, checker):
        """상품을 성공적으로 찾는 시나리오 테스트"""
        # Mock HTML 응답
        mock_html = """
        <html>
            <body>
                <div class="product_item">
                    <a href="/products/11111111">상품1</a>
                    <div class="product_title">상품1</div>
                </div>
                <div class="product_item">
                    <span class="ad_badge">광고</span>
                    <a href="/products/22222222">광고상품</a>
                </div>
                <div class="product_item">
                    <a href="/products/33333333">상품2</a>
                    <div class="product_title">상품2</div>
                </div>
            </body>
        </html>
        """
        
        mock_response = Mock()
        mock_response.text = mock_html
        mock_request.return_value = mock_response
        
        # 상품 33333333 찾기
        result = checker.check_product_rank("테스트", "33333333", max_page=1)
        
        assert result is not None, "상품을 찾지 못함"
        assert result['product_id'] == "33333333"
        assert result['absolute_rank'] == 2, "순위 계산 오류 (광고 제외 2위여야 함)"
    
    @patch('src.ranking.checker.safe_request')
    def test_상품_찾기_실패(self, mock_request, checker):
        """상품을 찾지 못하는 시나리오 테스트"""
        mock_html = """
        <html>
            <body>
                <div class="product_item">
                    <a href="/products/11111111">상품1</a>
                </div>
            </body>
        </html>
        """
        
        mock_response = Mock()
        mock_response.text = mock_html
        mock_request.return_value = mock_response
        
        # 존재하지 않는 상품 99999999 찾기
        result = checker.check_product_rank("테스트", "99999999", max_page=1)
        
        assert result is None, "존재하지 않는 상품을 찾았다고 잘못 반환함"
    
    @patch('src.ranking.checker.safe_request')
    def test_광고_제외_순위_계산(self, mock_request, checker):
        """광고를 제외한 순위가 올바르게 계산되는지 테스트"""
        # 광고 2개 + 일반 상품 3개
        mock_html = """
        <html>
            <body>
                <div class="product_item">
                    <span>광고</span>
                    <a href="/products/ad1">광고1</a>
                </div>
                <div class="product_item">
                    <a href="/products/11111111">상품1</a>
                </div>
                <div class="product_item">
                    <span>광고</span>
                    <a href="/products/ad2">광고2</a>
                </div>
                <div class="product_item">
                    <a href="/products/22222222">상품2</a>
                </div>
                <div class="product_item">
                    <a href="/products/33333333">상품3</a>
                </div>
            </body>
        </html>
        """
        
        mock_response = Mock()
        mock_response.text = mock_html
        mock_request.return_value = mock_response
        
        # 상품3 찾기 (광고 제외 3위)
        result = checker.check_product_rank("테스트", "33333333", max_page=1)
        
        assert result is not None
        assert result['absolute_rank'] == 3, "광고 제외 순위 계산 오류"


class TestRankAccuracy:
    """실제 네이버 쇼핑 순위 체크 정확도 테스트"""
    
    @pytest.mark.integration
    @pytest.mark.parametrize("keyword,product_id,expected_rank_range", [
        # 실제 테스트 케이스를 여기에 추가
        # ("삼성 갤럭시 S24", "12345678", (10, 20)),  # 10~20위 사이
        # ("아이폰 15", "87654321", (1, 10)),  # 1~10위 사이
    ])
    def test_실제_순위_체크(self, keyword, product_id, expected_rank_range):
        """
        실제 네이버 쇼핑에서 순위 체크 정확도 테스트
        
        주의: 이 테스트는 실제 네이버 쇼핑에 요청을 보냅니다.
        테스트 케이스는 사용자가 직접 추가해야 합니다.
        """
        checker = RankChecker()
        max_page = (expected_rank_range[1] // 20) + 2
        
        result = checker.check_product_rank(keyword, product_id, max_page=max_page)
        
        assert result is not None, f"상품 {product_id}를 찾을 수 없음"
        
        actual_rank = result['absolute_rank']
        min_rank, max_rank = expected_rank_range
        
        assert min_rank <= actual_rank <= max_rank, \
            f"순위 {actual_rank}위가 예상 범위 {min_rank}~{max_rank}위를 벗어남"


# pytest 실행 시 표시할 마커 정의
pytest.mark.integration = pytest.mark.integration
