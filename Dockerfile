FROM mysql:8.0-debian

# docker is only used for integration testing, so ignoring security is acceptable

ENV MYSQL_ROOT_PASSWORD=12345678
ENV MYSQL_DATABASE=test

RUN apt update && apt upgrade -y \
    && apt install -y build-essential wget libmysqlclient-dev libssl-dev

COPY . .

RUN cc -fPIC -c crypsi_mysqludf.c -I /usr/include/mysql
RUN cc -shared -o crypsi_mysqludf.so crypsi_mysqludf.o
RUN cp crypsi_mysqludf.so  /usr/lib/mysql/plugin/

COPY ./scripts/init.sql /docker-entrypoint-initdb.d/