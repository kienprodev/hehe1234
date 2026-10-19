**Phân tích mã độc**




Dynamic Analysis 
1.Định nghĩa
Phân tích động là phương pháp nghiên cứu mã độc bằng cách trực tiếp thực thi mẫu mã độc trong một môi trường cô lập được kiểm soát an toàn để giám sát,ghi nhận và đánh giá toàn bộ hành vi thực tế của nó theo thời gian thực.
1.2. Mục đích
Mục định của việc phân tích động là:
- Quan sát hành vi của mẫu mã độc trong thực tế nó sẽ xác định chính xác mã đọc làm gì khi nào kích hoạt tạo file nào sửa registry ra sao kết nối với ip hay domain nào 
- Giúp nhanh chóng thu thập được các dâu vết xâm nhập như c2,domain,url tải payload,khóa resgistry khởi động phục vụ cho việc điều tra kẻ tấn công
- Phân loại được loại mã độc và mục tiêu tấn công  của chúng để đưa ra phương án tối ưu cho việc ứng phó với sự cố kịp thời
- Giúp hỗ trợ trong quá trình dịch ngược khi payload thực thi gốc trong bộ nhớ và tự giải nén trên trong ram
1.3 Ưu điểm
- Vượt qua kĩ thuật làm rối và nén mã :
Khi mình thực hiện phân tích tính 1 chương trình trở ngại lớn nhất đối với phương pháp này là payload đã được mã hóa,polymorphic hay obfuscated nhưng khi phân tích động chúng buộc phải giải mã về dạng mã máy gốc trong bộ nhớ để chạy khiến việc dịch ngược trở nên dễ dàng
-> từ đó ta có thể thấy được dynamic analysis  giúp chúng ta có thể tiết kiệm được thời gian mà vẫn hiểu được 80% payload thay vì ngồi đọc từng dòng code asm đã bị obfuscated trong ida 
1.4.Hạn chế
Mặc dù ta đã thấy được những ưu điểm của nó là rất lớn nhưng đi đối với nó là những hạn chế cũng mang tiềm ẩn nguy cơ rủi ro rất cao :
- **Nguy cơ lây nhiễm môi trường thật** : Nếu chúng ta  lỡ cấu hình máy ảo không chuẩn để hở mạng nội bộ hay chia sẻ folder với máy thật hoặc con malware nó có kỹ thuật vm escape từ đó nó có thể tiếp cận và xâm nhập với máy thật 
- **Dễ bị đánh lừa bởi kĩ thuật né tránh:**
- ***Kĩ thuật Anti-Vm-Detection*** :khi nó check được rằng môi trường mà nó đang xâm nhập là VM (bằng cách check được địa chỉ MAC của VM ,số lượng cpu cores, dung lượng ram,hành vi của con chuột nó sẽ nằm im hoặc chúng có cơ chế tự hủy
-  ***Kĩ thuật time-bomb***: mã độc sẽ gọi sleep hàng tiếng đồng hồ hoặc kiếm tra mốc thời gian hệ thống trong tương lai mới kích hoạt hành vi độc hại
- Hơn nữa độ bao phủ của kĩ thuật phân tích động còn ***hạn chế nó chỉ quan sát được nhánh thực thi với điều kiện môi tường tại thời điểm chạy***. nếu mã độc yêu cầu tham số dòng lệnh củ thể môi trường domain active directory hoặc lệnh phản hồi từ c2 sever thì hành vi nguy hiểm phía sau sẽ không bao giờ được bộc lộ

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
