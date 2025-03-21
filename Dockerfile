# Build stage
FROM python:3.12-alpine3.21 AS builder
WORKDIR /app

# Install build dependencies
RUN apk update && apk add --no-cache \
    cmake \
    build-base \
    linux-headers \
    gcompat \
    git \
    openssl-dev

# Build liboqs and liboqs-python
RUN CORES=$(nproc) && \
    echo "Detected $CORES cores." && \
    export CMAKE_BUILD_PARALLEL_LEVEL=$CORES && \
    export MAKEFLAGS="-j$CORES" && \
    git clone --depth=1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git && \
    cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel $CORES && \
    cmake --build liboqs/build --target install && \
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python

# Runtime stage
FROM python:3.12-alpine3.21
LABEL authors="Laszlo Popovics"
LABEL vendor="AIvantGuard AG"
LABEL version="1.0.0"
WORKDIR /app

# Install only runtime dependencies
RUN apk update && apk add --no-cache openssl
ENV PYTHONPATH=/app
RUN mkdir -p /root/_oqs/lib
COPY --from=builder /usr/local/lib/liboqs* /root/_oqs/lib
COPY --from=builder /usr/local/lib/cmake/liboqs /usr/local/lib/cmake/liboqs/
COPY --from=builder /usr/local/lib/pkgconfig/liboqs.pc /usr/local/lib/pkgconfig/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs/
COPY --from=builder /app/liboqs-python /app/liboqs-python
# Copy application code and certificate
COPY aioneguard /app/aioneguard
COPY conf/rootCA.pem /app/rootCA.pem

# Final setup and cleanup
RUN pip install --upgrade pip setuptools certifi pydantic websockets requests pytz boto3 \
    pycryptodome cryptography pynacl argon2-cffi --no-cache-dir && \
    cat /app/rootCA.pem >> /usr/local/lib/python3.12/site-packages/certifi/cacert.pem && \
    cd liboqs-python && \
    pip install --no-cache-dir . && \
    rm -rf /app/rootCA.pem /root/.cache/pip /tmp/* /var/tmp/* /var/cache/apk/* && \
    mkdir -p /app/data /app/conf /app/logs /app/temp

CMD ["python", "aioneguard/aioneguardchain/store/main.py", "start", "$INSTANCE_ID"]