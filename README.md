# remind-node-intermidiate

# 환경 변수

- `.env.example` 파일의 이름을 `.env`로 변경하고 아래 내용 채워야함

```sh
SERVER_PORT= 서버 포트
DATABASE_URL=mysql://계정이름:비밀번호@주소:포트/DB명
ACCESS_TOKEN_SECRET=JWT 생성을 위한 비밀키
REFRESH_TOKEN_SECRET=JWT 생성을 위한 비밀키
```

# 실행 방법

- 필요한 패키지 설치

```sh
yarn
```

- 서버 실행 ( 배포용 )

```sh
yarn start
```

- 서버 실행 ( 개발용 )

```sh
yarn dev
```

# API 명세서

# ERD
