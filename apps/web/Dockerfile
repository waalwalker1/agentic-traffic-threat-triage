# Build stage
FROM node:20-alpine AS build

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY apps/web/ ./apps/web/
RUN npx vite build --config apps/web/vite.config.ts

# Production stage
FROM nginx:alpine
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
