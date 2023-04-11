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


g_expire_seconds = Gauge('jks_monitor_expire_seconds', 'Description of gauge', ['path', 'alias', 'cn'])


class Config(BaseSettings):
    jks_path: list[str]
    jks_password: list[SecretStr] = ["changeit"]

    port: int = 8000
    refresh_seconds: int = 60
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
    ks = jks.KeyStore.load(jks_path, jks_password)
    for alias, pk in list(ks.private_keys.items()):
        logger.debug(f"Found alias={alias}")
        pk_type = None
        if isinstance(pk, jks.PrivateKeyEntry):
            cert_result = pk.cert_chain[0][1]
            public_cert = _get_cert(pk.cert_chain[0][1])
            pk_type = "PrivateKeyEntry"
        elif isinstance(pk, jks.TrustedCertEntry):
            public_cert = _get_cert(pk.cert)
            pk_type = "TrustedCertEntry"

        cert_expires = datetime.strptime(
            str(public_cert.get_notAfter(), "ascii"), "%Y%m%d%H%M%SZ")

        cert_expires_sec = (cert_expires - datetime.now()).total_seconds()
        cn = "Undefined"
        for name, value in public_cert.get_subject().get_components():
            if name.lower() == b'cn':
                cn = str(value, 'utf-8')
        g_expire_seconds.labels(path=jks_path, alias=alias, cn=cn).set(cert_expires_sec)


def run():
    try:
        config = Config()
    except pydantic.ValidationError as e:
        logger.error(f"Failed to load config: {e.errors()}")
        sys.exit(2)

    if config.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    for jks_path in config.jks_path:
        print(config.jks_path)
        if not os.path.isfile(jks_path):
            logging.error(f"JKS_PATH: {jks_path} is not a file")
            sys.exit(1)
    print(len(config.jks_password))
    if  len(config.jks_path) != len(config.jks_password) or len(config.jks_password) != 1:
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
                print(idx, pass_idx, password.get_secret_value(),)
                update_metrics(jks_path, password.get_secret_value())
                time.sleep(config.refresh_seconds)
    except KeyboardInterrupt:
        logger.info("Stop")