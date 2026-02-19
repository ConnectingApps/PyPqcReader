FROM python:3.11-slim

# Install build dependencies for OpenSSL
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    perl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and compile OpenSSL 3.5.0
WORKDIR /tmp
RUN wget https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz \
    && tar -xzf openssl-3.5.0.tar.gz \
    && cd openssl-3.5.0 \
    && ./Configure --prefix=/usr/local/openssl-3.5 --openssldir=/usr/local/openssl-3.5 \
    && make -j$(nproc) \
    && make install \
    && cd .. \
    && rm -rf openssl-3.5.0 openssl-3.5.0.tar.gz

# Set up library path to use custom OpenSSL
ENV LD_LIBRARY_PATH=/usr/local/openssl-3.5/lib64:/usr/local/openssl-3.5/lib:$LD_LIBRARY_PATH
ENV PATH=/usr/local/openssl-3.5/bin:$PATH

# Create symlink for libssl.so.3 if needed
RUN ldconfig /usr/local/openssl-3.5/lib64 /usr/local/openssl-3.5/lib || true

# Set working directory for the application
WORKDIR /app

# Copy package directory and install it
COPY package/ /app/package/
RUN pip install --no-cache-dir /app/package/

# Copy main.py
COPY main.py /app/

# Set the entry point
ENTRYPOINT ["python", "/app/main.py"]
