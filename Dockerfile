FROM rust:alpine
LABEL Name=neptunejs Version=0.0.1
COPY . /root/
COPY ./Cargo.docker.toml /root/Cargo.toml
WORKDIR /root/
RUN rustup target add x86_64-unknown-linux-gnu
# CMD ["sh", "-c", "/root/init.sh"]
