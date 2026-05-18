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
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV CSP_CONNECT_HTTP=http://localhost:8000 \
    CSP_CONNECT_WS=ws://localhost:8000
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx && \
    touch /var/run/nginx.pid && chown nginx:nginx /var/run/nginx.pid
USER nginx
EXPOSE 80
CMD ["/bin/sh", "-c", "envsubst '${CSP_CONNECT_HTTP} ${CSP_CONNECT_WS}' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'"]
