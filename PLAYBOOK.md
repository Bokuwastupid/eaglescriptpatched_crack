# Playbook: переламати цей crackme заново

Інструкція на випадок, якщо автор оновить білд (новий PyArmor, інший ендпоінт,
змінена схема JSON, новий Python, додатковий anti-tamper). Іди по кроках — на
кожному є перевірка "що повинно бути" і "що робити якщо не так".

Усі команди з `d:\projects\reversepython\` (або перекладеш шляхи куди зібрано).

---

## 0. Що тобі знадобиться

```bash
pip install frida frida-tools pyinstxtractor-ng pyinstaller
```

Бінарники в `tools/`: `pycdc.exe`, `pycdas.exe`. Якщо їх немає — `pycdc` береться
з https://github.com/zrax/pycdc (збери або скачай Windows-білд).

Також корисно мати `x64dbg` — не для кряка, а щоб швидко подивитись GUI target'а
при першому запуску.

---

## 1. Перевіряємо, що target все ще PyInstaller + PyArmor

Без цього припущення весь плейбук неактуальний.

```bash
pyinstxtractor-ng <NEW_TARGET>.exe
ls <NEW_TARGET>.exe_extracted/
```

**Ознаки що це все ще той самий клас target:**
- є `python3XX.dll`
- є `pyarmor_runtime_000000/pyarmor_runtime.pyd`
- є `main.pyc` (або інша точка входу з `Possible entry point:` у виводі)

Декомпілюй entry point і шукай маркер PyArmor:

```bash
tools/pycdc.exe <NEW_TARGET>.exe_extracted/main.pyc | head -5
```

Має бути:
```python
from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000...')
```

**Якщо PyArmor прибрали** — просто декомпілюй `main.pyc` і читай Python-код.
Цей плейбук тоді не потрібен.

**Якщо з'явився новий обфускатор (Nuitka, Themida, VMProtect)** — плейбук не
спрацює, потрібна інша стратегія.

---

## 2. Знайти правильний процес

PyInstaller onefile створює **двох процесів** з однаковою назвою: батько
(розпаковувач) і дитина (Python runtime). Нам потрібна дитина.

Запусти target вручну (подвійний клік), потім:

```bash
python probe.py
```

У виводі шукай рядок з `python3XX.dll` — PID поруч і є правильним. Мій
`probe.py` автоматично перебирає кандидатів; якщо він не бачить Python DLL —
дитина ще не стартанула, просто запусти ще раз за 2 секунди.

**Якщо target змінив назву** — онови константу `TARGET` у `probe.py`,
`run_bypass.py`, `launcher.py`. Порівняння через `.lower()` і `in`, тому
часткова збіжність працює.

**Якщо Python версія змінилась** (наприклад з 3.12 на 3.13) — нічого міняти
не треба, regex `^python3\d+\.dll$` покриває.

---

## 3. Зрозуміти як target перевіряє ключ

Три можливі світи:

| Патерн | Як визначити | Що робити |
|---|---|---|
| Офлайн-перевірка (локальна) | В розпакованому `main.pyc` немає `requests/urllib3`, і при натисканні Verify немає мережевих викликів | Плейбук "B" нижче |
| Онлайн + проста JSON відповідь | Є `requests`, сервер повертає `{"status":"ok/error"}` або подібне | Плейбук "A" — цей таргет |
| Онлайн + підписана відповідь (RSA/ECDSA) | Є `cryptography` і target на клієнті валідує підпис | Плейбук "B" (хук Python-рівня) — мережевий мок не працює |

Щоб зрозуміти який з них — спочатку швидка розвідка через recon-скрипт (крок 4).
Якщо в логах побачиш `https://...` URL, `POST`, `application/json` — це А.

---

## 4. Recon: дивимось що всередині відбувається при Verify

```bash
python run_recon.py
```

У терміналі з'явиться запрошення `>>> ENTER to ARM <<<`. **Порядок дій:**

1. Введи у GUI target'а будь-який ключ.
2. Наведи курсор на кнопку Verify (не натискай).
3. Enter у терміналі — побачиш `=== RECORDING ON ===`.
4. Одразу клікни Verify.
5. Коли з'явиться "Invalid product key" (або що там у нового target'а) —
   Enter у терміналі → `=== RECORDING OFF ===`.

**Що шукати у зібраному логу:**

- `https://...` — ендпоінт. Запиши його.
- `POST` / `GET` — метод.
- `content-length: N` — розмір запиту і відповіді.
- `application/json` — підтвердження JSON.
- `{"status":"..."}` / `{"valid":...}` — **справжня схема відповіді сервера**.
  Це те, що треба буде підмінити в bypass.
- `UUID ...` / `Get-CimInstance` — підтвердження що використовується HWID.

**Якщо лог забитий шумом Tkinter** (`update`, widget-id, `check_dpi_scaling`)
— додай нові шумові слова до `NOISE` regex у [recon.js](recon.js). Я вже додав
типові, але CustomTkinter може принести нові.

**Якщо в логу нічого цікавого** — target може використовувати `http.client`
напряму або інші мережеві бібліотеки. Тоді додай хуки на:
- `send` / `sendall` / `recv` у `python3XX.dll`
- або одразу `SSL_write` / `SSL_read` у `libssl-3.dll` (див. наступний крок)

---

## 5A. Онлайн-шлях: TLS response rewriter

Це метод яким я зламав оригінальну версію. Логіка: сервер повертає JSON,
target його парсить і дивиться на поле типу `status`. Ми перехоплюємо момент
коли OpenSSL віддає розшифрований буфер у Python, і підміняємо тіло.

### 5A.1. Підтвердити що є libssl-3.dll

У виводі `probe.py` мусить бути `libssl-3.dll @ C:\...\Temp\_MEI...\libssl-3.dll`.

**Якщо немає** — target перейшов на інший TLS-бекенд (наприклад schannel через
WinHTTP, або statically-linked OpenSSL). Тоді хукай:
- `WinHttpReadData` / `WinHttpSendRequest` у `winhttp.dll`
- або шукай власний libssl-подібний модуль у списку з `probe.py`

### 5A.2. Запустити bypass і подивитись на реальну відповідь

```bash
python run_bypass.py
```

Введи ключ, Verify. У терміналі:

```
[ssl_read 134B] HTTP/1.1 400 Bad Request\r\ndate: ...\r\ncontent-length: 50\r\n...
[ssl_read  50B] {"status":"error","message":"Invalid product key"}
```

Запиши точний формат відповіді. **Це єдине що треба оновити в `bypass.js`:**

```javascript
const SUCCESS_BODY = '{"status":"ok","message":"License verified"}';
```

Якщо у нової версії схема інша — наприклад `{"valid":true,"token":"..."}` —
постав туди правильну структуру. Якщо в успішній відповіді є токен або
підпис який target далі валідує — дивись крок 5A.4.

### 5A.3. Перевірити що rewrite відбувся

Після Verify у логу має з'явитись:
```
[+] rewrote headers+body -> 200 OK, CL=44
[+] rewrote JSON body -> {"status":"ok",...}
```

І GUI має пройти далі. Якщо rewrite був а GUI не пройшов — схема неправильна.
Подивись на наступний `[ssl_read]` після обходу — можливо сервер повертає щось
більше (редірект, додатковий виклик). У такому випадку target робить кілька
HTTP викликів і треба підміняти всі. Розширюй `rewrite()` щоб впізнавати всі
варіанти.

### 5A.4. Якщо target валідує підпис відповіді

Ознаки: в `cryptography` є, у відповіді є поле типу `signature`/`sig`/`token`
яке виглядає як base64, і після підміни ми бачимо у `recon.js` виклик типу
`InvalidSignature` або помилку `cryptography.exceptions`.

Шляхи:
1. **Перехопити перевірку підпису** — хук на `Signature.verify` через
   Python-рівень. Складно (PyArmor).
2. **Хук на CPython `PyObject_IsTrue`** коли результат верифікації
   повертається. Простіше — завжди повертати True.
3. **Дампнути приватний ключ сервера** — нереально.
4. **Хукнути точку після верифікації** у libssl або нижче — неможливо, бо
   це вже в Python-land.

Для (2) треба через `recon.js` знайти виклик типу `verify` або `is_valid`
і форсити повернення. Це складніше ніж TLS rewrite, але робочий підхід.

---

## 5B. Офлайн-шлях: хук Python-рівня

Якщо target перевіряє ключ локально (без мережі) — дані про правильний
ключ десь у коді. PyArmor шифрує байткод, але **рядки з'являються у пам'яті
в момент порівняння**.

Той самий `recon.js` з кроку 4 покаже:

```
[cmp str] "ABCD-1234-WXYZ" == "TEST"    ← лівий аргумент - справжній ключ!
```

Або:

```
[unieq] "<hash з введеного>" == "<очікуваний hash>"
```

Далі два варіанти:
1. **Знайти і використовувати справжній ключ** — просто вводь його у GUI.
2. **Примусово повернути True** — хук на `PyObject_RichCompareBool`, коли
   викликається порівняння з підозрілим правим аргументом — повертати 1.

Приклад хука на примусовий True:

```javascript
Interceptor.attach(findExp(pyMod, "PyObject_RichCompareBool"), {
    onEnter(args) {
        const a = reprObj(args[0]), b = reprObj(args[1]);
        // tight match — must target the license check specifically
        if (a && b && a.length > 10 && b.length > 10 && args[2].toInt32() === 2) {
            this.force = true;
        }
    },
    onLeave(retval) {
        if (this.force) retval.replace(1);
    }
});
```

Тонка настройка умови `if (...)` під конкретний target — інакше ламаєш
випадкові порівняння і програма падає.

---

## 6. Зібрати standalone exe

Коли `bypass.js` працює — пакуємо:

```bash
pyinstaller --onefile --noconsole --name LicenseBypass ^
    --add-data "bypass.js;." ^
    --add-data "<NEW_TARGET>.exe;." ^
    launcher.py
```

Не забудь оновити у [launcher.py](launcher.py) константу:
```python
TARGET_EXE = resource_path("<NEW_TARGET>.exe")
TARGET_NAME = "<new_target>.exe"
```

Результат у `dist/LicenseBypass.exe`.

---

## 7. Поширені проблеми і як їх діагностувати

### Frida не бачить `python3XX.dll` у процесі
Атачишся до батька, а не до дитини. Використовуй `probe.py` або логіку
`wait_for_child` з `run_bypass.py`.

### `Module.getExportByName is not a function`
Frida 17 змінила API. Використовуй `mod.findExportByName(name)` на
конкретному інстансі Module, не глобальну функцію.

### Хук не ставиться, bypass.js "мовчить"
`libssl-3.dll` ще не завантажений. Polling + `LoadLibraryExW` хук вже
реалізований у bypass.js — просто дочекайся кілька секунд.

### GUI проходить "License verified", але закривається
Target робить другий запит після першого (наприклад, за конфігурацією
з сервера). Подивись `[ssl_read]` логи — побачиш ще одну пару
headers+body. Додай її в `rewrite()`.

### Антивірус зносить `LicenseBypass.exe`
Очікувана поведінка — PyInstaller + cross-process injection = класична
сигнатура зловреда. Додай у виключення або не пакуй в exe, запускай
з Python.

### `script has been destroyed`
Target закрився раніше ніж скрипт встиг виконати RPC-виклик. Додай
timeout перед `script.exports_sync.start()` або перевіряй що процес ще
живий через `dev.enumerate_processes()`.

### Новий PyArmor перевіряє "чи нас дебажать"
PyArmor має anti-debug режими. Якщо target при запуску одразу закривається
або падає — спробуй `frida-trace` без хуків, просто attach. Якщо падає
тільки під Frida — треба стелс. Варіанти:
1. Запускати target без Frida, атачитись через 2 секунди після старту.
2. Використовувати `frida-gadget` через DLL injection замість stealth attach.
3. Дивитись звідки приходить сигнал завершення — часто це перевірка
   `sys.gettrace()` або `ctypes.windll.kernel32.IsDebuggerPresent()`.

---

## 8. Чек-ліст "від нуля до готового exe"

1. [ ] `pyinstxtractor-ng <target>.exe` — розпакував
2. [ ] `pycdc main.pyc` — підтвердив PyArmor
3. [ ] `probe.py` — знайшов PID дитини, бачу `python3XX.dll` + `libssl-3.dll`
4. [ ] `run_recon.py` ARM → Verify → DISARM — зібрав URL, метод, схему
5. [ ] `run_bypass.py` → Verify → бачу `[ssl_read]` з реальним JSON
6. [ ] Оновив `SUCCESS_BODY` у `bypass.js` під побачену схему
7. [ ] Повторив Verify → GUI пройшов
8. [ ] `pyinstaller ... launcher.py` — зібрав standalone
9. [ ] `dist/LicenseBypass.exe` подвійний клік → працює

---

## 9. Куди рости далі

- **Автоматичний schema detection** — у `bypass.js` робити першу рев'ю
  відповіді (помилкову), діставати ключі, і генерувати success JSON з
  інвертованими значеннями. Прибирає ручну роботу при зміні схеми.
- **Frida Gadget замість Frida CLI** — вбудувати gadget у target, не
  треба буде окремого launcher'а.
- **Підпис відповіді** — якщо колись з'явиться, рішення через Python-рівень
  хук або взагалі підкидати target'у локальний приватний ключ через
  `os.environ` чи подібне.
