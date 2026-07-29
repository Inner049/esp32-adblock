# План коммерческого ESP32-C3 AdBlock продукта

## Цель
Превратить текущий DIY-проект в готовый к продаже аппаратный блокировщик рекламы — без перепрошивки, без программирования.

## Принятые решения (пользователь)

1. **LED**: Не управлять программно, оставить как есть (постоянно горит)
2. **WiFi хранение**: LittleFS (файл)
3. **AP SSID**: AdBlock-Setup
4. **Captive Portal**: Нет
5. **Upstream DNS**: Настраивается в веб-интерфейсе с тестом задержек
6. **BOOT кнопка**: Удержание 3s после старта > сброс настроек и AP mode
7. **STA timeout**: Ничего не делать

---

## Задачи

### 1. WiFi Setup Mode (AP + веб-конфиг)

**BOOT логика:**
`
1. Проверить BOOT кнопку (GPIO 9) удержана ли более 3s:
   L- Да > удалить /wifi.cfg > перезагрузка в AP mode
   
2. Читаем /wifi.cfg (LittleFS)
   +- Файл есть > STA mode, коннектимся
   ¦   +- Успех > MAIN MODE (DNS + Dashboard)
   ¦   L- Fail > STA mode, коннектимся
   L- Файл нет > SETUP MODE
`

**SETUP MODE:**
- WiFi.mode(WIFI_AP)
- AP: AdBlock-Setup без пароля
- IP: 192.168.4.1
- DNS сервер на AP: UDP 53, отвечает 192.168.4.1 на любые запросы
- Web-страница: список WiFi сетей + выбор + поле пароля + кнопка 'Сохранить и запустить'

**WiFi скан:**
int n = WiFi.scanNetworks();
for (int i = 0; i < n; i++) ssids.push_back({WiFi.SSID(i), WiFi.RSSI(i)});

**Сохранение:** /wifi.cfg > ssid=... + pass=... > ESP.restart()

### 2. Factory Reset

BOOT кнопка 3s — сбрасывает настройки  
UI кнопка 'Сбросить настройки' > /factory-reset (удалить /wifi.cfg, ребут)

### 3. Настраиваемый Upstream DNS

**Файл /dns.cfg:**
upstream=9.9.9.9

**DNS список:**
- Quad9: 9.9.9.9
- Cloudflare: 1.1.1.1
- Google: 8.8.8.8
- OpenDNS: 208.67.222.222

**UI:**
- Выпадающий список + поле 'Свой DNS'
- 'Проверить выбранный' (15 UDP запросов)
- 'Проверить все' (цикл по всем)

**Тест:**
- 15 UDP-запросов к example.com (A-record)
- Timeout 3s/запрос, max 45s
- JSON ответ: {min: 5, avg: 12, max: 25}

---

## План разработки

1. WiFi Setup Mode — AP + DNS redirect + веб-страница + сохранение
2. BOOT кнопка эффективный 3s детект
3. Factory Reset UI + эндпоинт
4. Upstream DNS UI + тест
5. добавь украинскую и русскую локализацию в оба вебинтерфейса чтобы их всего было 3 на выбор (укр, рус, англ)
6. Тестирование: clean boot > AP > настройка > STA работа

---

## Риски

| Риск | Mitigation |
|------|-----------|
| BOOT кнопка не обнаружена | GPIO 9 с подтягивающим резистором 10k |
| LittleFS ошибка | Проверка при чтении файла, fallback на дефолты |
| DNS тест зависнет | Timeout 3s/запрос |

---

## Технические детали

### BOOT кнопка детект
`cpp
pinMode(9, INPUT_PULLUP);  // GPIO 9 BOOT на SuperMini
if (digitalRead(9) == LOW) {
  uint32_t t0 = millis();
  while (digitalRead(9) == LOW && millis() - t0 < 3000) delay(10);
  if (millis() - t0 >= 3000) {
    LittleFS.remove("/wifi.cfg");  // сброс
    ESP.restart();
  }
}
`

### AP DNS Redirect (упрощённый)
- На AP запустить UDP сервер на 53 порту
- Любой запрос > ответ с 192.168.4.1 (A-record)

### Файлы для изменения
- src/main.cpp — основные изменения
- src/secrets.h — удалить (или сделать optional)
- platformio.ini — возможно добавить build flags

### UI страницы
1. /setup — AP режим (WiFi настройка)
2. / — основной Dashboard (сейчас) + Factory Reset + DNS настройка

---

## Готово к реализации
