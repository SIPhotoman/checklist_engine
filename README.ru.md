## 📖 Read this in other languages

- [Русский](README.ru.md)
- [English](README.md)

---

# Checklist Engine

Зашифрованные исполняемые аварийные чек-листы.
Классы-контракты пишутся как обычный Python,
офлайн компилируются в зашифрованный бандл, а на устройстве расшифровываются
поштучно — при наличии ключа.

## Модель

* **Step** (*контракт*) — одно атомарное действие: `run(ctx, **params)` и
  необязательный `undo(ctx)`.
* **Checklist** — упорядоченный список пар `(имя_шага, параметры)`.
* **Context** — `dict`, общий для всех шагов одного прогона: шаг кладёт туда
  свои результаты и читает результаты предыдущих шагов.
* **OnError** — политика обработки отказа, задаваемая в момент вызова:
  `ABORT`, `CONTINUE` или `ROLLBACK`, плюс `retries` и `retry_delay`.

## Файлы

| Файл | Назначение |
|---|---|
| `crypto.py` | AES-GCM-SIV и вывод ключа (Argon2id → HKDF-SHA3-512) |
| `contracts.py` | `Step`, `Checklist`, `Context`, `OnError`, типы отчётов |
| `vault.py` | `build_bundle` (офлайн-компилятор), `SecureRegistry` (загрузчик) |
| `engine.py` | `ChecklistRunner` — исполняет чек-листы, применяет политику |
| `example.py` | Примеры контрактов и рабочее сквозное демо |

Установка: `pip install -r requirements.txt` (нужен `cryptography>=44.0`).
Запуск демо: `python example.py`.

## Жизненный цикл

**1. Пишем контракты** обычным Python в одном файле:

```python
from contracts import Checklist, Step

class ConnectToServer(Step):
    name = "connect"

    def run(self, ctx, host="127.0.0.1", port=8443, **_):
        ctx["link"] = open_socket(host, port)
        return "connected"

    def undo(self, ctx):
        ctx.pop("link", None).close()

class SecureDispatch(Checklist):
    name = "secure_dispatch"
    steps = [
        ("connect", {"host": "10.0.0.7", "port": 8443}),
        ("channel", {}),
        ("rotate_keys", {"generation": 7}),
        ("send", {"command": "ARM_SAFE_MODE"}),
    ]
```

**2. Компилируем в зашифрованный бандл** (офлайн, на доверенной машине):

```python
from vault import build_bundle

build_bundle({"connect": ConnectToServer,
              "secure_dispatch": SecureDispatch}, key, "secure_bundle.py")
```

На выходе — импортируемый `.py` со словарём `{имя: base64_шифротекст}`.
Исходного кода в нём нет.

**3. Загружаем и запускаем** на устройстве:

```python
from engine import ChecklistRunner
from vault import load_bundle
from contracts import OnError

runner = ChecklistRunner(load_bundle("secure_bundle.py", key))
report = runner.run("secure_dispatch",
                    on_error=OnError(OnError.ROLLBACK, retries=2))
print(report.summary())   # secure_dispatch: OK -- 4/4 steps ok in 0.002s
```

`runner.run()` принимает также класс или экземпляр `Checklist` либо
встроенный список `[(имя_шага, параметры), ...]`. Запись может быть
`"name"`, `("name",)` или `("name", params)`.

## Семантика исполнения

Для каждого шага: создать экземпляр класса, вызвать `run(ctx, **params)`;
при исключении повторить ещё до `retries` раз (с паузой `retry_delay`, тот же
экземпляр); если шаг всё равно упал — применить политику:

* `ABORT` — остановиться сразу (по умолчанию; безопасно для аварийных
  сценариев).
* `CONTINUE` — записать отказ и перейти к следующему шагу.
* `ROLLBACK` — вызвать `undo(ctx)` у выполненных шагов в обратном порядке и
  остановиться. Исключение внутри `undo` записывается, но никогда не
  заслоняет исходную ошибку.

Каждая попытка попадает в `ChecklistReport` (`.ok`, `.results`,
`.rolled_back`, `.duration`, `.summary()`). Политика, переданная в `run()`,
перекрывает объявленную в самом чек-листе.

## Криптография

* **Шифр: AES-GCM-SIV** (RFC 8452). Имя записи привязано как associated data,
  поэтому шифротекст нельзя незаметно переставить в другой слот бандла.
* **Вывод ключа** (`crypto.derive_key`) — Argon2id с `t=3` итерациями,
  `p=4` полосами, `m=2^16 KiB` (64 МиБ), выход 64 байта, затем
  HKDF-SHA3-512 до нужной длины. Аргумент `info` (по умолчанию
  `b"checklists-engine/v1/bundle-key"`) привязывает ключ к назначению.

  ```python
  key = crypto.derive_key(passphrase, salt, info=b"my-fleet/v2")
  ```

  Argon2id требует 64 МиБ ОЗУ на один вывод — убедитесь, что плата их
  выделит. Соль (16 байт) храните рядом с бандлом; она не секретна, но должна
  быть уникальной.
* `encrypt`/`decrypt` принимают сырой ключ
  16/24/32 байта.

### Модель доверия

Ключ — единственная граница. Расшифрованный код контракта исполняется с
полными правами, как любой другой модуль процесса: это **конфиденциальность
и целостность контрактов, а не песочница**. Кто может подставить ключ — тот
может выполнить произвольный код, ключ защищайте соответственно.

Файл бандла **разбирается, а не исполняется** (`vault.read_bundle_file` через
`ast` читает только литеральные присваивания `BUNDLE`/`META`). Исполнение
файла позволило бы любому, кто может в него писать, запустить код ещё до
единственной проверки ключа.

## Правила написания контрактов

`inspect.getsource` захватывает только тело класса, но не строки `import` из
модуля. Загрузчик заранее подставляет `Step`, `Checklist`, `Context`,
`OnError`, `StepResult`, `ChecklistReport` и модули `time`, `os`, `json`,
`struct`, `hashlib`, `hmac`, `binascii`, `math`, `random`. **Всё остальное
импортируйте внутри метода.** Каждая запись бандла должна определять ровно
один подкласс `Step` или `Checklist`, и класс должен лежать в настоящем
`.py`-файле.

## Примечания

* Расшифровка ленивая и кэшируется: запись расшифровывается при первом
  обращении, дальше переиспользуется готовый объект класса.
