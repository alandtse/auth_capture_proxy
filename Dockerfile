# https://stackoverflow.com/questions/53835198/integrating-python-poetry-with-docker/54763270#54763270

FROM python:3.9

# See https://github.com/opencontainers/image-spec/blob/master/annotations.md
LABEL name="auth_capture_proxy"
LABEL version="1.2.1"
LABEL vendor="alandtse"
LABEL org.opencontainers.image.title="auth_capture_proxy"
LABEL org.opencontainers.image.version="1.2.1"
LABEL org.opencontainers.image.url="https://github.com/alandtse/auth_capture_proxy"
LABEL org.opencontainers.image.documentation="https://github.com/alandtse/auth_capture_proxy"

# ENV no longer adds a layer in new Docker versions,
# so we don't need to chain these in a single line
ENV YOUR_ENV=${YOUR_ENV}
ENV PYTHONFAULTHANDLER=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONHASHSEED=random
ENV PIP_NO_CACHE_DIR=off
ENV PIP_DISABLE_PIP_VERSION_CHECK=on
ENV PIP_DEFAULT_TIMEOUT=120
ENV POETRY_VERSION=1.1.4

ARG YOUR_ENV

# System deps:
RUN pip install "poetry==$POETRY_VERSION"

# Copy only requirements to cache them in docker layer
WORKDIR /code
COPY poetry.lock pyproject.toml /code/

# Project initialization:
RUN poetry config virtualenvs.create false \
  && poetry install $(test "$YOUR_ENV" == production && echo "--no-dev") --no-interaction --no-ansi

# Creating folders, and files for a project:
COPY . /code

# Now do something with it!
# Perhaps run a command:
# CMD authcaptureproxy --my --options --etc
# or expose a port:
# EXPOSE 443/tcp
