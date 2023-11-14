FROM nginx:1.25.3
# RUN apt update -y && apt install net-tools iputils-ping -y
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d