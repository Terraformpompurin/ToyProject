<<<<<<< HEAD
# ===== 빌드 단계 =====
=======
>>>>>>> a4b2f72 (k8s 포트포워딩 배포 지원)
FROM node:18-alpine AS builder

WORKDIR /app

<<<<<<< HEAD
# 의존성 복사 및 설치
COPY package*.json ./
RUN npm install

# 소스 코드 복사
COPY . .

# 프로덕션 빌드 (정적 파일 생성)
RUN npm run build

# ===== 실행 단계 (nginx로 정적 파일 서빙) =====
FROM nginx:alpine

# nginx 설정 복사
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 빌드 결과물 복사
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
=======
COPY package*.json ./
RUN npm install

COPY . .

ARG VITE_API_URL=/scan
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
>>>>>>> a4b2f72 (k8s 포트포워딩 배포 지원)
