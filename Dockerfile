# Dockerfile with the correct sage installation. This executes the uov_ref/uov.py script
# which generates all test vectors for the hardware testing. Run:
# sudo docker buildx build -t uov:latest .
# sudo docker run -v "$PWD/uov_ref/data:/sage/uov_ref/data" uov:latest

FROM sagemath/sagemath:develop
ENV PYTHONUNBUFFERED=1
USER root
WORKDIR /sage
RUN sage -pip install pycryptodome
COPY . .
WORKDIR /sage/uov_ref
CMD ["sage", "uov.py"]
