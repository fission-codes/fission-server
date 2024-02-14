FROM burntsushi/cross:x86_64-unknown-linux-musl
RUN apt-get update
RUN apt-get install -y libpq-dev build-essential
