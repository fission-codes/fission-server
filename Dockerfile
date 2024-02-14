FROM ubuntu:23.10
RUN apt-get update
RUN apt-get install -y wget gcc build-essential perl libpq-dev
# Get this to play nicely when run on NixOS
# https://github.com/cross-rs/cross/issues/260#issuecomment-520193756
RUN mkdir -m777 /opt/rust /opt/cargo
ENV RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN wget --https-only --secure-protocol=TLSv1_2 -O- https://sh.rustup.rs | sh /dev/stdin -y
RUN rustup target add x86_64-unknown-linux-gnu
RUN printf '#!/bin/sh\nexport CARGO_HOME=/opt/cargo\nexec /bin/sh "$@"\n' >/usr/local/bin/sh
RUN chmod +x /usr/local/bin/sh
