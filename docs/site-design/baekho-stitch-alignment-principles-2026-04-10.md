# 백호 Stitch 정렬 원칙 2026-04-10

## 목적

- `baekho.app`를 Stitch `Baekho` 데스크톱 시안에 더 가깝게 맞출 때 흔들리지 않는 구현 기준을 만든다.
- 홈 `/`와 데모 `/demo`를 각각 따로 꾸미지 않고, 같은 브랜드 리듬으로 정렬한다.
- 이후 Codex가 디자인 수정을 진행할 때 이 문서를 먼저 참고하도록 한다.

## 기준 화면

- Stitch 프로젝트: `projects/12921925345120282971`
- 랜딩 기준 화면: `Baekho Landing Page`
- 데모 기준 화면: `백호 (Baekho) - 설명 가능한 보안 플랫폼`
- 고정 기준: `deviceType = DESKTOP`

## 핵심 원칙

### 1. Wordmark는 `white title + micro badge`

- 현재 `baekho.app` topbar의 `백호` wordmark 색은 `#FFFFFF`를 사용한다.
- 이는 Stitch 원안의 cyan보다 `백호 = white tiger`라는 브랜드 의미 일관성을 우선한 결정이다.
- `백호` 텍스트와 보조 배지는 한 줄에서 타이트하게 붙어야 한다.
- 배지는 `설명용 label`이지 버튼이 아니므로, 작고 얇은 micro pill 비율을 유지한다.
- 홈 `/`와 데모 `/demo`는 같은 gap, 같은 font-size, 같은 baseline offset을 써야 한다.

### 2. Topbar는 `page-scoped fixed topbar`로 고정

- 홈 `/`는 `topbar + site-nav + topbar-actions` 구조를 유지한다.
- 데모 `/demo`는 `demo-topbar + demo-nav + demo-topbar-actions` 구조를 유지한다.
- 제보 `/report`는 `demo-topbar + demo-topbar-inner + demo-nav + demo-topbar-actions` 구조를 재사용해 데모 `/demo`와 같은 topbar 리듬을 유지한다.
- 제보 `/report`의 topbar는 별도 시각 스타일을 만들지 않고, 가능한 범위에서 데모 `/demo` topbar 규칙을 그대로 재사용한다.
- 다만 `report` 본문 래퍼에는 홈 내부 카드용 `demo-shell` 같은 범용 클래스를 재사용하지 않고, topbar 재사용 범위를 헤더 쪽 클래스로 제한한다.
- 홈과 데모는 같은 브랜드 리듬을 공유하되, `shared header`(`app-topbar`, `app-topnav`, `header-shared.css`)로 다시 합치지 않는다.
- 제보 페이지도 예전 `brand-mark + brand-copy` 헤더로 돌아가지 않고, 동일한 wordmark/header 리듬을 유지한다.
- 데모 헤더 오른쪽에 `Desktop Console / Public Demo` 같은 상태 텍스트를 다시 올리지 않는다.
- 홈/데모 topbar 정보 구조는 `홈 / 데모 / 제보 / 기술 / 운영 근거`를 기본값으로 유지한다.
- topbar 구조를 바꿔야 할 때는 이 원칙을 깨는 변경인지 먼저 검토하고, 특별한 요청이 없는 한 현재 구조를 유지한다.

### 3. 히어로는 `짧은 주장 + 짧은 설명`

- 헤드라인은 강한 한 문장으로 끝내고, 본문은 1~2문장 안에 끝낸다.
- 히어로 본문은 `무엇을 분석하는가`, `왜 행동 전에 보여주는가`, `현재 공개 범위`만 남긴다.
- 기능 목록은 본문에 길게 나열하지 말고, 아래 highlight chip이나 trust band로 내린다.

### 4. 첫 화면은 `설명`보다 `판단 장면`

- Stitch 쪽은 긴 소개보다 결과가 보이는 장면이 먼저 온다.
- 홈에서는 오른쪽 콘솔 카드가, 데모에서는 결과 패널이 먼저 읽혀야 한다.
- 따라서 상단 네비와 히어로 문장은 짧고 날카롭게 유지한다.

### 5. 구분은 `border`보다 `tonal layering`

- 카드 경계는 1px 실선보다 배경 톤 차이와 옅은 outline으로 만든다.
- 섹션 분리는 강한 선 대신 surface 차이, spacing, blur로 해결한다.
- 카드 윤곽선은 꼭 필요할 때만 약하게 쓰고, 기본 인상은 tone separation으로 만든다.

### 6. 장식은 `분위기`까지만

- 호랑이 워터마크, 상징 아이콘, 과한 배경 이미지는 지양한다.
- 필요한 장식은 radial glow, subtle gradient, glass topbar 정도까지만 허용한다.
- 브랜드 인상은 마스코트보다 타이포와 여백에서 만든다.

### 7. 데모는 `console-first`

- 데모 상단은 소개 페이지처럼 보이면 안 되고, 제품 콘솔처럼 보여야 한다.
- 소개 문장보다 `샘플 결과`, `위험 점수`, `근거`, `다음 행동`이 먼저 읽혀야 한다.
- 네비 항목과 보조 문구가 많아지면 결과 패널 존재감이 줄어드는지 먼저 점검한다.

## 즉시 적용 규칙

- 상단 `백호` wordmark 색은 `#FFFFFF`
- 상단 `백호` wordmark는 특별한 요청이 없는 한 흰색을 유지한다
- wordmark gap은 `8px`
- badge는 `10px`급 micro label 비율 유지
- topbar 전역 메뉴는 `홈 / 데모 / 제보 / 기술 / 운영 근거`
- topbar 메뉴 폰트 크기는 현재 기준 `0.94rem`을 유지하고, 체감 차이는 구조/간격 변경 여부부터 먼저 확인한다
- `report` topbar는 데스크톱/모바일 모두 demo topbar와 같은 background, padding, nav gap, active 표현을 우선 재사용한다
- 홈 hero body는 2문장 이내
- 홈 hero highlight chip은 3개 정도로 유지
- 홈/데모 topbar는 `page-scoped fixed topbar` 구조를 유지하되, 동일한 wordmark 정렬 체계를 사용

## 수정 우선순위

1. wordmark 색상·위치 정렬
2. 홈 히어로 문장량 축소
3. 데모 상단 네비 정보량 축소
4. 카드 border 약화와 tonal layering 강화
5. 하단 섹션의 문서형 리듬을 더 시각형으로 압축

## 이번 턴 적용 대상

- 홈 `/` hero body를 Stitch landing처럼 더 짧게 줄인다.
- 홈과 데모의 `백호` wordmark 색을 브랜드 의미 기준의 흰색으로 유지한다.
- 이 문서를 이후 `baekho.app` 디자인 수정의 로컬 기준 문서로 사용한다.
