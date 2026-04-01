FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG VITE_BACKEND_HTTP=http://localhost:8000
ARG VITE_BACKEND_WS=ws://localhost:8000
ARG VITE_TRANSPORT_SEAL_ENABLED=true
ARG VITE_TRANSPORT_KEY_B64=
ARG VITE_API_KEY=
ENV VITE_BACKEND_HTTP=$VITE_BACKEND_HTTP \
    VITE_BACKEND_WS=$VITE_BACKEND_WS \
    VITE_TRANSPORT_SEAL_ENABLED=$VITE_TRANSPORT_SEAL_ENABLED \
    VITE_TRANSPORT_KEY_B64=$VITE_TRANSPORT_KEY_B64 \
    VITE_API_KEY=$VITE_API_KEY
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx && \
    touch /var/run/nginx.pid && chown nginx:nginx /var/run/nginx.pid
USER nginx
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
