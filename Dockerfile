ARG BASE_IMAGE=python:3.11-alpine
ARG WORKDIR=/app

FROM ${BASE_IMAGE} as base
# Renew (https://stackoverflow.com/a/53682110):
ARG WORKDIR

ENV PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1

WORKDIR ${WORKDIR}

FROM base as builder
ARG YOUR_ENV=production

ENV YOUR_ENV=${YOUR_ENV} \
    PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.4.0

RUN apk add --no-cache gcc musl-dev
#ibffi-dev musl-dev postgresql-dev
RUN pip install "poetry==$POETRY_VERSION"

COPY pyproject.toml poetry.lock README.md ./
# if your project is stored in src, uncomment line below
# COPY src ./src
# or this if your file is stored in $PROJECT_NAME, assuming `myproject`
COPY jks_monitor ./jks_monitor

# Project initialization:
RUN poetry config virtualenvs.in-project true && \
    poetry install $(test "$YOUR_ENV" == production && echo "--only main") --no-interaction --no-ansi && \
    poetry build

FROM base as final
# Renew (https://stackoverflow.com/a/53682110):
ARG WORKDIR

# For options, see https://boxmatrix.info/wiki/Property:adduser
RUN adduser app -DHh ${WORKDIR} -u 1000
USER 1000
#RUN apk add --no-cache libffi libpq
COPY --from=builder --chown=app:app /app/.venv ./.venv
COPY --from=builder --chown=app:app /app/dist .
RUN ./.venv/bin/pip install *.whl
EXPOSE 8000
CMD ["/app/.venv/bin/jks_monitor_cli"]