import os
import logging
import sys
import time

import OpenSSL
import jks

from datetime import datetime
import prometheus_client
import pydantic
from prometheus_client import Gauge, start_http_server
from pydantic import BaseSettings, SecretStr
from typing import Any

logging.basicConfig()
logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)


g_expire_seconds = Gauge('jks_monitor_expire_seconds', 'Seconds to cert expire', ['path', 'alias', 'cn','type'])


class Config(BaseSettings):
    jks_path: list[str]
    jks_password: list[SecretStr] = ["changeit"]

    port: int = 8000
    refresh_seconds: int = 3600
    platform_metrics: bool = False
    debug: bool = False

    class Config:
        env_prefix = ""
        env_file = '.env'
        case_sensitive = False

        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> Any:
            if field_name in ('jks_path', 'jks_password'):
                return [str(x) for x in raw_val.split(',')]
            return cls.json_loads(raw_val)


def _get_cert(certificate):
    """
    Gets the correct certificate depending of the encoding

    :param certificate: str
    """
    ASN1 = OpenSSL.crypto.FILETYPE_ASN1
    PEM = OpenSSL.crypto.FILETYPE_PEM
    if certificate[0] == 0x30:
        public_cert = OpenSSL.crypto.load_certificate(ASN1, certificate)
    else:
        public_cert = OpenSSL.crypto.load_certificate(PEM, certificate)
    return public_cert


def update_metrics(jks_path, jks_password):
    #https://github.com/saltstack/salt/blob/2bd55266c8ecc929a3a0a9aec1797a368c521072/salt/modules/keystore.py#L2

    ks = jks.KeyStore.load(jks_path, jks_password)

    entries = ks.entries.items()

    if entries:
        for entry_alias, cert_enc in entries:
            logger.debug(f"Found alias={entry_alias}")
            pk_type = None
            if isinstance(cert_enc, jks.PrivateKeyEntry):
                public_cert = _get_cert(cert_enc.cert_chain[0][1])
                pk_type = "PrivateKey"
            elif isinstance(cert_enc, jks.TrustedCertEntry):
                public_cert = _get_cert(cert_enc.cert)
                pk_type = "TrustedCert"

            cert_expires = datetime.strptime(
                str(public_cert.get_notAfter(), "ascii"), "%Y%m%d%H%M%SZ")

            cert_expires_sec = (cert_expires - datetime.now()).total_seconds()
            cn = "Undefined"
            for name, value in public_cert.get_subject().get_components():
                if name.lower() == b'cn':
                    cn = str(value, 'utf-8')

            g_expire_seconds.labels(path=jks_path, alias=entry_alias, cn=cn, type=pk_type).set(cert_expires_sec)


def run():
    try:
        config = Config()
    except pydantic.ValidationError as e:
        logger.error(f"Failed to load config: {e.errors()}")
        sys.exit(2)

    if config.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    for jks_path in config.jks_path:
        if not os.path.isfile(jks_path):
            logging.error(f"JKS_PATH: {jks_path} is not a file")
            sys.exit(1)

    if not (len(config.jks_path) == len(config.jks_password) or len(config.jks_password) == 1):
        logger.error(f"JKS_PASSWORD number of elements not equal")
        sys.exit(3)

    jks_password_single = True if len(config.jks_password) == 1 else False

    if not config.platform_metrics:
        prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
        prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
        prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)

    logger.info(f"Starting on port: {config.port}")
    start_http_server(config.port)
    try:
        while True:
            for idx, jks_path in enumerate(config.jks_path):
                pass_idx = 0 if jks_password_single else idx
                password = config.jks_password[pass_idx]
                update_metrics(jks_path, password.get_secret_value())

            time.sleep(config.refresh_seconds)
    except KeyboardInterrupt:
        logger.info("Stop")