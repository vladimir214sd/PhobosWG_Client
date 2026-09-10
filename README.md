# Phobos WireGuard Client for Windows

<p align="center">
  <img src="assets/logo.png" width="160" height="160" alt="Phobos WireGuard Logo" />
</p>

<p align="center">
  <b>Ультракомпактный (~1 МБ) нативный графический клиент для протокола Phobos WireGuard под Windows.</b>
</p>

<p align="center">
  <a href="https://github.com/vladimir214sd/PhobosWG_Client/releases/latest"><img src="https://img.shields.io/github/v/release/vladimir214sd/PhobosWG_Client?color=red&label=Скачать%20EXE" alt="Release" /></a>
  <a href="https://github.com/Ground-Zerro/Phobos"><img src="https://img.shields.io/badge/Исходный%20проект-Ground--Zerro%2FPhobos-blue" alt="Upstream Phobos" /></a>
  <img src="https://img.shields.io/badge/Платформа-Windows%2010%20%2F%2011-blue" alt="Platform" />
  <img src="https://img.shields.io/badge/Размер-1.07%20МБ-brightgreen" alt="Size" />
  <img src="https://img.shields.io/badge/Лицензия-MIT-green" alt="License" />
</p>

---

## 🔗 Исходный проект Phobos

Данный клиент разработан для работы с серверной частью **[Ground-Zerro/Phobos](https://github.com/Ground-Zerro/Phobos)** — расширением протокола WireGuard со встроенной защитой от цензуры (DPI-блокировок) с помощью маскировки под протокол STUN и симметричного XOR/CRC8-обфусцирования.

---

## ✨ Особенности

- 🪶 **Экстремально малый размер (~1.07 МБ)**: Полный графический клиент с вшитым сетевым драйвером Wintun (~400 КБ) и криптографическим движком. Никаких тяжелых игровых движков (WebGPU/Vulkan/DirectX) или WebView — чистый Win32 API.
- 🛡 **Самостоятельный VPN-туннель**: Полноценная реализация туннелирования на базе `boringtun` (Cloudflare) и `wintun`. Официальный WireGuard не требуется.
- ⚡ **Архитектура Zero-Process**: Никаких вызовов внешних консольных утилит (`route.exe`, `netsh.exe`). Маршруты, DNS, MTU и IP-адреса настраиваются напрямую через системные Win32 API (`iphlpapi.dll`) за микросекунды — без малейшего мерцания окон консоли или терминала.
- 🎭 **Поддержка маскировки Phobos**: Встроенное STUN-оборачивание/разворачивание пакетов и симметричное XOR/CRC8-обфусцирование трафика для обхода блокировок и DPI.
- 🎨 **Нативный интерфейс в стиле WireGuard**: Двухколоночный интерфейс со списком туннелей, цветными индикаторами статуса, детальной карточкой пира, графиком скорости в реальном времени и журналом событий.
- 📥 **Поддержка Drag & Drop**: Добавление туннелей простым перетаскиванием архива `.tar.gz` или файла `.conf` в окно программы.
- 🔒 **Полная автономность**: Драйвер `wintun.dll` вшит в бинарник и при необходимости автоматически извлекается.

---

## 🚀 Быстрый старт

### Скачивание готового файла
1. Скачайте **`phobos-client.exe`** со страницы **[Последнего релиза](https://github.com/vladimir214sd/PhobosWG_Client/releases/latest)**.
2. Запустите программу и подтвердите запрос прав администратора (необходимо для сетевого адаптера Wintun).
3. Перетащите в окно архив конфигурации `.tar.gz` (или нажмите кнопку **«➕ Добавить»**).
4. Нажмите **«Подключить»**.

---

## 🛠 Сборка из исходников

### Требования
- **ОС**: Windows 10 / 11 (x64)
- **Rust**: 1.75+ (`stable-x86_64-pc-windows-msvc`)
- **Windows SDK**: установленный `rc.exe` (для компиляции ресурсов иконки приложения)

### Команды для сборки

```cmd
# Клонирование репозитория
git clone https://github.com/vladimir214sd/PhobosWG_Client.git
cd PhobosWG_Client

# Сборка оптимизированного релизного бинарника
cargo build --release
```

Готовый файл будет находиться по пути:
`target/release/phobos-companion.exe` (переименуйте в `phobos-client.exe`).

---

## ⚙️ Архитектура

```text
[ Приложения Windows ]
         │
         ▼
[ Виртуальный адаптер Wintun (IP / MTU 1280) ]
         │
         ▼
[ Userspace WireGuard Engine (BoringTun) ]
         │ (Шифрование ChaCha20-Poly1305)
         ▼
[ Phobos Obfuscator (XOR / CRC8 / Key) ]
         │
         ▼
[ STUN Packet Wrapper (Magic Cookie 0x2112A442) ]
         │
         ▼
[ Физический UDP Сокет (привязанный к шлюзу) ]
         │
         ▼
   [ ИНТЕРНЕТ ] ──► [ Phobos Сервер ]
```

---

## 📄 Лицензия

MIT License