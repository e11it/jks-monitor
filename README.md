# JKS Monitor

Экспортирует метрику сертификатов, секунды до истечения, из JKS файла(ов).

* `JKS_PATH` - путь до JKS файлов, разделитель запятая
* `JKS_PASSWORD` - пароль для JKS. Задается либо один на всех или для каждого. По умолчанию: `changeit`.

Параметры можно задавать через `.env` файл.

Пример запуска для двух JKS файлов с паролем по умолчанию.
```shell
JKS_PATH="test_data/kafka-rest.keystore.jks,test_data/kafka_all.jks" poetry run jks_monitor_cli
```

Пример метрик:
```shell
localhost:8000/metrics
# HELP jks_monitor_expire_seconds Seconds to cert expire
# TYPE jks_monitor_expire_seconds gauge
jks_monitor_expire_seconds{alias="kafka_rest_000_0",cn="kafka_rest_000_0",path="test_data/kafka-rest.keystore.jks",type="PrivateKey"} 6.3098359928717e+07
jks_monitor_expire_seconds{alias="kafka_999_9",cn="999_9",path="test_data/kafka_all.jks",type="TrustedCert"} 3.65086994928129e+08
```