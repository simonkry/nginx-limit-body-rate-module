FROM alpine

RUN apk add --no-cache apache2 php php-apache2

RUN mkdir --parents /var/www/html/upload && \
    chown --recursive apache:apache /var/www/html/upload

ARG SERVER_NAME=www.example.com
RUN echo "<html><body><h1>It works! From ${SERVER_NAME}</h1></body></html>" > /var/www/html/index.html

COPY httpd.conf /etc/apache2/httpd.conf
RUN sed -i "s|ServerName <TO_BE_SET>|ServerName ${SERVER_NAME}|" /etc/apache2/httpd.conf

CMD ["httpd", "-D", "FOREGROUND"]