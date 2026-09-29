# BÁO CÁO KỸ THUẬT: PHÂN TÍCH TĨNH MÃ ĐỘC CƠ BẢN (BASIC STATIC MALWARE ANALYSIS)

- **Học phần:** Phân tích Mã độc (Malware Analysis)
- **Giảng viên hướng dẫn:** Vương Lê
- **Thời hạn:** 1 tuần | **Thang điểm:** 100 điểm
- **Mục tiêu hoàn thành:**
  - Nắm vững và đọc hiểu kiến trúc tệp thực thi PE (Portable Executable) trên Windows.
  - Thành thạo bộ công cụ phân tích tĩnh tiêu chuẩn công nghiệp (*Exeinfo PE, PEStudio, Strings, CFF Explorer, Detect It Easy, FLOSS*).
  - Trích xuất toàn diện các chỉ số thỏa hiệp sơ bộ (IOCs - Hashes, C2 Domains/IPs, Registry, File Paths, Suspicious Strings).
  - Đánh giá mức độ rủi ro, phân loại họ mã độc và dự đoán hành vi nguy hại mà **không cần thực thi tệp** trong môi trường động.

---

## MỤC LỤC

1. [PHẦN 1: LÝ THUYẾT NỀN TẢNG (40 ĐIỂM)](#phần-1-lý-thuyết-nền-tảng-40-điểm)
   - [1.1. Bản chất & Cơ chế Phân tích Tĩnh (Static Analysis) (10đ)](#11-bản-chất--cơ-chế-phân-tích-tĩnh-static-analysis-10đ)
     - 1.1.1. Định nghĩa kỹ thuật
     - 1.1.2. Mục đích cốt lõi
     - 1.1.3. Ưu điểm nổi bật
     - 1.1.4. Hạn chế và thách thức kỹ thuật
     - 1.1.5. So sánh toàn diện: Static Analysis vs. Dynamic Analysis
   - [1.2. Nghiên cứu & Ứng dụng Bộ Công cụ Phân tích Tĩnh (20đ)](#12-nghiên-cứu--ứng-dụng-bộ-công-cụ-phân-tích-tĩnh-20đ)
     - 1.2.1. Exeinfo PE (Phát hiện Packer, Obfuscation & Compiler)
     - 1.2.2. PEStudio (Đánh giá chỉ số rủi ro & Tự động đối chiếu MITRE ATT&CK)
     - 1.2.3. Strings & FLOSS (Trích xuất chuỗi thô & Giải mã Stack Strings)
     - 1.2.4. CFF Explorer (Kiểm tra sâu cấu trúc PE & Chỉnh sửa PE Header)
     - 1.2.5. Công cụ bổ trợ đề xuất: Detect It Easy (DIE) & Capa
   - [1.3. Các Dữ liệu Trọng yếu Cần Quan tâm Khi Phân tích Tĩnh Tệp PE (10đ)](#13-các-dữ-liệu-trọng-yếu-cần-quan-tâm-khi-phân-tích-tĩnh-tệp-pe-10đ)
     - 1.3.1. Giá trị Băm & Nhận dạng (MD5, SHA256, Imphash, SSDEEP)
     - 1.3.2. Cấu trúc PE Headers (DOS Header, File Header, Optional Header, Subsystem)
     - 1.3.3. Các phân vùng (Sections), Entropy & Tỷ lệ Virtual Size / Raw Size
     - 1.3.4. Bảng hàm nhập (Import Address Table - IAT) & Các Windows API nguy hiểm
     - 1.3.5. Bảng hàm xuất (Export Address Table - EAT)
     - 1.3.6. Tài nguyên nhúng (Resources - `.rsrc`) & Dữ liệu nối đuôi (Overlay)
     - 1.3.7. Điểm gọi ngầm (TLS Callbacks) & Chữ ký số (Digital Certificate)
2. [PHẦN 2: THỰC HÀNH PHÂN TÍCH MẪU MÃ ĐỘC THỰC TẾ (60 ĐIỂM)](#phần-2-thực-hành-phân-tích-mẫu-mã-độc-thực-tế-60-điểm)
   - [2.1. Quy trình Phân tích Tĩnh Chuẩn 5 Bước (SOP)](#21-quy-trình-phân-tích-tĩnh-chuẩn-5-bước-sop)
   - [2.2. Mẫu Phân Tích 01: Ransomware WannaCry (Mssecsvc.exe Dropper) (30đ)](#22-mẫu-phân-tích-01-ransomware-wannacry-mssecsvcexe-dropper-30đ)
     - 2.2.1. Thông tin định danh & Metadata
     - 2.2.2. Đánh giá Đóng gói (Packer) & Entropy Phân vùng
     - 2.2.3. Phân tích Các API đáng ngờ (Suspicious APIs / IAT)
     - 2.2.4. Trích xuất Chuỗi (Strings) & IOCs sơ bộ
     - 2.2.5. Dấu hiệu Persistence & Cơ chế Phán đoán Hành vi
     - 2.2.6. Kết luận & Đánh giá Rủi ro
   - [2.3. Mẫu Phân Tích 02: Trojan Stealer / RAT (RedLine Stealer Payload) (30đ)](#23-mẫu-phân-tích-02-trojan-stealer--rat-redline-stealer-payload-30đ)
     - 2.3.1. Thông tin định danh & Metadata
     - 2.3.2. Đánh giá Đóng gói & Trình biên dịch (.NET / ConfuserEx)
     - 2.3.3. Phân tích Các API & Phương thức độc hại
     - 2.3.4. Trích xuất Chuỗi (Strings, C2 Server, Regex thu thập dữ liệu)
     - 2.3.5. Dấu hiệu Persistence & Evasion
     - 2.3.6. Kết luận & Đánh giá Rủi ro
   - [2.4. Khung Biểu Mẫu Báo Cáo Chuẩn (Standard Report Template)](#24-khung-biểu-mẫu-báo-cáo-chuẩn-standard-report-template)
3. [TỔNG KẾT & TÀI LIỆU THAM KHẢO](#tổng-kết--tài-liệu-tham-khảo)

---

# PHẦN 1: LÝ THUYẾT NỀN TẢNG (40 ĐIỂM)

## 1.1. Bản chất & Cơ chế Phân tích Tĩnh (Static Analysis) (10đ)

### 1.1.1. Định nghĩa kỹ thuật
**Phân tích tĩnh mã độc (Static Malware Analysis)** là phương pháp kiểm tra, mổ xẻ cấu trúc nhị phân, mã máy, siêu dữ liệu (metadata), và tài nguyên của một tệp tin đáng ngờ **mà hoàn toàn không thực thi (không kích hoạt chạy)** tệp đó trên hệ điều hành.

Quá trình này bao gồm việc đọc các trường trong tiêu đề tệp (headers), tính toán chữ ký số và mã băm mật mã (cryptographic hashes), trích xuất chuỗi ký tự (strings), phân tích bảng hàm nhập/xuất (imports/exports), và dịch ngược mã máy (disassembly/decompilation) thành Assembly hoặc mã nguồn bậc cao (C, C#, Java).



### 1.1.2. Mục đích cốt lõi
1. **Xác định tính chất tệp (Triage & Categorization):** Phân loại nhanh tệp nghi vấn là lành tính (Benign), phần mềm quảng cáo/không mong muốn (PUA/Adware), hay mã độc nguy hiểm (Ransomware, Trojan, Rootkit).
2. **Thu thập Chỉ số Thỏa hiệp sơ bộ (Initial Indicators of Compromise - IOCs):** Trích xuất nhanh các địa chỉ IP, C2 Domain, URL tải payload, tên tiến trình mục tiêu, khóa Registry hoặc tên Mutex mà mã độc chuẩn bị sử dụng.
3. **Phát hiện Kỹ thuật Che giấu (Packer / Obfuscation Detection):** Kiểm tra xem mẫu nhị phân có bị nén (packed), bảo vệ bằng máy ảo (VMProtect/Themida), hay mã hóa payload bên trong không để lựa chọn chiến lược giải nén (unpacking) phù hợp.
4. **Định hướng cho Phân tích Động & Dịch ngược Chuyên sâu:** Khoanh vùng các hàm API nguy hiểm (như `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) để đặt sẵn Breakpoint chính xác khi đưa vào Debugger (x64dbg/x32dbg).

### 1.1.3. Ưu điểm nổi bật
- **An toàn tuyệt đối (Safety):** Do không chạy tệp tin, phân tích viên loại bỏ hoàn toàn nguy cơ lây nhiễm mã độc sang máy phân tích hoặc làm rò rỉ dữ liệu qua mạng LAN.
- **Tốc độ thực hiện nhanh (High Speed & Scalability):** Việc trích xuất mã băm, chuỗi và IAT chỉ mất vài giây đến vài phút; có thể tự động hóa trên hàng triệu mẫu tệp bằng script (YARA, Python-pefile).
- **Bao quát toàn diện các luồng thực thi (Code Coverage):** Phân tích tĩnh cho phép đọc và rà soát được tất cả các nhánh rẽ điều kiện (conditional branches), hàm ngầm, mã xử lý sự kiện phụ mà trong phân tích động có thể không bao giờ được kích hoạt (do thiếu điều kiện môi trường hoặc thời gian).
- **Vô hiệu hóa kỹ thuật Anti-Dynamic/Evasion:** Bỏ qua được các kỹ thuật phát hiện máy ảo (Anti-VM), phát hiện Debugger (Anti-Debugging), kỹ thuật Sleep Acceleration hoặc kỹ thuật Geofencing (chỉ chạy ở một quốc gia chỉ định).

### 1.1.4. Hạn chế và thách thức kỹ thuật
- **Bất lực trước Packer và Cryptor hiện đại:** Nếu mã độc bị đóng gói bằng UPX, Themida, Enigma Protector, VMP, phần lớn mã nguồn thực thi đã bị nén/mã hóa. Phân tích tĩnh cơ bản chỉ thấy được phần mã của stub giải nén (Unpacking Stub) chứ không thể đọc được mã độc thực thụ bên dưới.
- **Che giấu API thông qua Dynamic Resolution:** Mã độc tinh vi không khai báo hàm trong IAT mà sử dụng cặp API `LoadLibrary` + `GetProcAddress` hoặc duyệt thủ công cấu trúc PEB (Process Environment Block) và giải băm API (API Hashing/ROR13), khiến bảng IAT trông hoàn toàn "vô hại".
- **Chuỗi bị xáo trộn (String Obfuscation):** Các chuỗi nhạy cảm (C2 IP, lệnh PowerShell, đường dẫn file) thường bị mã hóa XOR, RC4, Base64 hoặc chia nhỏ thành từng ký tự gán trên Stack (Stack Strings), khiến lệnh `strings` thông thường không thể đọc được.
- **Đòi hỏi kiến thức cấu trúc nhị phân sâu:** Yêu cầu chuyên gia phải hiểu sâu về mã máy x86/x64, cấu trúc tệp tin Windows PE/Linux ELF và cơ chế bộ nhớ hệ điều hành.

### 1.1.5. So sánh toàn diện: Static Analysis vs. Dynamic Analysis

| Tiêu chí | Phân tích Tĩnh (Static Analysis) | Phân tích Động (Dynamic Analysis) |
| :--- | :--- | :--- |
| **Bản chất kỹ thuật** | Khám phá cấu trúc, mã nguồn, metadata của tệp **không thực thi**. | Quan sát hành vi, tiến trình, mạng, file/registry khi **cho tệp chạy thực tế**. |
| **Mức độ an toàn** | **Rất an toàn**, có thể phân tích trên máy làm việc cách ly logic. | **Tiềm ẩn rủi ro cao**, bắt buộc phải chạy trong Sandbox/VM cô lập mạng (Host-Only). |
| **Thời gian & Tốc độ** | Rất nhanh (vài giây đến vài phút cho triage sơ bộ). | Chậm hơn (cần thời gian quan sát từ 2 - 10 phút để mã độc bộc lộ hành vi). |
| **Độ phủ mã (Code Coverage)** | **100% không gian mã** (có thể duyệt mọi nhánh code, hàm ẩn, mã chết). | **Hạn chế** (chỉ ghi nhận được những luồng mã được kích hoạt trong phiên chạy đó). |
| **Đối phó Packer/Obfuscation**| Khó khăn, bị chặn bởi mã hóa, nén stub, xáo trộn chuỗi. | **Vượt qua dễ dàng**, vì mã độc bắt buộc phải tự giải nén lên RAM để CPU thực thi. |
| **Đối phó Kỹ thuật Chống phân tích**| Miễn nhiễm với Anti-VM, Sleep Delay, Human-Interaction Check. | Dễ bị qua mặt nếu mã độc phát hiện môi trường ảo hóa, Sandbox hoặc tắt mạng. |
| **Công cụ tiêu biểu** | Exeinfo PE, PEStudio, Strings, CFF Explorer, Ghidra, IDA Pro. | Procmon, Process Hacker, Wireshark, RegShot, Fiddler, Any.Run, Cuckoo. |

---

## 1.2. Nghiên cứu & Ứng dụng Bộ Công cụ Phân tích Tĩnh (20đ)

```
+----------------------------------------------------------------------------------------+
|                      BỘ CÔNG CỤ PHÂN TÍCH TĨNH TIÊU CHUẨN CÔNG NGHIỆP                  |
+----------------------------------------------------------------------------------------+
|  [Exeinfo PE]   ---> Nhận diện Compiler, Packer, Crypter & gợi ý Unpacker              |
|  [PEStudio]     ---> Chấm điểm chỉ số rủi ro (Indicators), Blacklist APIs, MITRE Map   |
|  [Strings/FLOSS]---> Trích xuất chuỗi ASCII, Unicode, Stack Strings, Decoded Strings   |
|  [CFF Explorer] ---> Xem & Sửa PE Header, Data Directories, Sections, Rebuild IAT      |
+----------------------------------------------------------------------------------------+
```

### 1.2.1. Exeinfo PE
<img width="558" height="254" alt="image" src="https://github.com/user-attachments/assets/a5e089d8-bd5d-4d04-87e9-95dc157b74a6" />

- **Chức năng chính:**
  - Là công cụ quét chữ ký số định dạng (Signature Scanner) chuyên dụng cực mạnh trên Windows.
  - Nhận dạng chính xác trình biên dịch (Compiler như Visual C++, Delphi, MinGW, .NET, Go, Rust, MASM).
  - Nhận diện các phần mềm đóng gói (Packer) và bảo vệ mã (Protector/Crypter) như UPX, ASPack, PECompact, VMProtect, Themida, ConfuserEx.
  - Kiểm tra xem tệp có chứa phần bù đuôi (Overlay) hoặc tệp nén giấu bên trong (ZIP, RAR, 7z) không.
- **Dữ liệu có thể trích xuất:**
  - Tên Packer và phiên bản tương ứng (ví dụ: `UPX 3.9x -> Markus & Laszlo`).
  - Địa chỉ điểm vào tệp (Entry Point - OEP thực hoặc OEP ảo).
  - Tình trạng tệp: Có bị Packed (Pack status), Unregistered Protector, Fake Headers hay không.
  - Lời khuyên/Gợi ý gỡ gói (Unpack info / Unpack tool suggestion) cho phân tích viên.
- **Ví dụ thông tin có giá trị trong điều tra malware:**
  - Khi mở mẫu malware vào Exeinfo PE, công cụ thông báo: `Packer: UPX 3.96 -> Markus Oberhumer`, đồng thời gợi ý lệnh unpack `upx -d file.exe`. Nhờ đó, phân tích viên biết ngay file đang bị nén bằng UPX và chỉ cần chạy 1 dòng lệnh để đưa file về trạng thái nguyên bản trước khi phân tích tiếp, tiết kiệm hàng giờ dịch ngược stub.
  

### 1.2.2. PEStudio
- **Chức năng chính:**
  - Là công cụ Triage (sàng lọc rủi ro) chuyên sâu hàng đầu dành cho các kỹ sư SOC/DFIR.
  - Tự động chấm điểm mức độ nguy hiểm của tệp dựa trên hệ thống luật định sẵn (Indicators) mà không cần nạp tệp lên mạng.
  - Tích hợp kiểm tra bảng băm trực tuyến với cơ sở dữ liệu VirusTotal.
  - Tự động đối chiếu các hàm API khả nghi với ma trận kỹ thuật tấn công **MITRE ATT&CK**.
  - Rà soát chữ ký số, danh sách chuỗi đen (Blacklisted Strings), tài nguyên khả nghi và TLS Callbacks.
- **Dữ liệu có thể trích xuất:**
  - Bộ mã băm đầy đủ: MD5, SHA1, SHA256, **Imphash** (Import Hash), SSDEEP.
  - Danh mục các phân vùng (Sections) kèm chỉ số Entropy (chỉ số ngẫu nhiên) và quyền hạn (Read, Write, Execute).
  - Danh sách chi tiết các thư viện DLL và hàm API được import, có đánh dấu đỏ các hàm độc hại (Blacklisted/Suspicious APIs).
  - Các chuỗi được phân loại theo danh mục: URL, IPv4, Registry, GUID, Debug Paths.
- **Ví dụ thông tin có giá trị trong điều tra malware:**
  - PEStudio gắn cờ đỏ cảnh báo: API `VirtualAllocEx` và `WriteProcessMemory` cùng xuất hiện, được gán nhãn MITRE ATT&CK là **T1055 (Process Injection)**. Phân tích viên ngay lập tức xác định được mẫu này mang hành vi chích mã độc vào tiến trình hệ thống hợp pháp để ẩn mình.

### 1.2.3. Strings (Sysinternals) & Mandiant FLOSS
- **Chức năng chính:**
  - Quét toàn bộ khối nhị phân để lọc ra các chuỗi ký tự in ấn được (printable characters) có độ dài từ 3 hoặc 4 ký tự trở lên.
  - Hỗ trợ trích xuất cả chuẩn mã hóa **ASCII (1-byte)** và **Unicode UTF-16LE (2-byte)**.
  - Phiên bản nâng cao **FLOSS (FireEye/Mandiant FLARE Obfuscated String Solver)** còn sử dụng giải thuật mô phỏng thực thi (emulation) để tự động giải mã các chuỗi được giấu trên Stack (Stack Strings) hoặc mã hóa XOR cơ bản.
- **Dữ liệu có thể trích xuất:**
  - Địa chỉ IP máy chủ điều khiển (C2 Server), tên miền (Domain Name), URL tải mã độc giai đoạn 2.
  - Tên các file tạm, file cấu hình, khóa Registry dùng để duy trì khởi động (Persistence).
  - Các câu lệnh hệ điều hành: `cmd.exe /c`, `powershell.exe -ExecutionPolicy Bypass`, `vssadmin delete shadows`.
  - Thông điệp đe dọa đòi tiền chuộc (Ransom Note), địa chỉ ví tiền mã hóa (Bitcoin, Monero), email liên hệ của hacker.
  - Đường dẫn biên dịch tệp (PDB Path) chứa tên tài khoản hoặc môi trường phát triển của kẻ tấn công (ví dụ: `C:\Users\Ivan\Desktop\Trojan\Release\payload.pdb`).
- **Ví dụ thông tin có giá trị trong điều tra malware:**
  - Khi chạy `strings -a sample.exe`, xuất hiện dòng: `http://update-microsoft-service[.]com/gate.php?id=` và `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. Điều này cung cấp ngay lập tức 2 chỉ số IOC quan trọng: Domain C2 để đưa vào hệ thống Firewall/SIEM chặn đứng kết nối, và vị trí mã độc cắm rễ khởi động cùng Windows.

### 1.2.4. CFF Explorer
- **Chức năng chính:**
  - Bộ biên tập và mổ xẻ cấu trúc Portable Executable (PE32 cho x86 và PE32+ cho x64) cực kỳ mạnh mẽ.
  - Cho phép xem, chỉnh sửa toàn bộ các trường trong DOS Header, NT Headers, File Header, Optional Header.
  - Quản lý các Data Directories: Export Directory, Import Directory, Resource Directory, Exception Directory, Relocation Directory.
  - Hỗ trợ tính toán lại Checksum, chỉnh sửa Section Headers, dump dữ liệu, mở Hex Editor và thay đổi quyền hạn bộ nhớ.
- **Dữ liệu có thể trích xuất:**
  - Kiến trúc CPU mục tiêu (`Machine: 0x014C` cho x86 hoặc `0x8664` cho x64).
  - Dấu thời gian biên dịch gốc (**TimeDateStamp**).
  - Các cờ bảo vệ hệ thống trong `DllCharacteristics`: Hỗ trợ **ASLR** (Address Space Layout Randomization), **DEP** (Data Execution Prevention), SafeSEH.
  - Chi tiết từng Section: `VirtualAddress`, `VirtualSize`, `RawAddress`, `RawSize`, `Characteristics` (quyền Read/Write/Execute).
  - Cây tài nguyên nhúng (Resources): Kiểm tra các tệp `.ico`, `.manifest`, hoặc các PE nhị phân con được giấu trong mục `BIN`/`RCDATA`.
- **Ví dụ thông tin có giá trị trong điều tra malware:**
  - Trong tab `Import Directory`, phân tích viên thấy danh sách Import chỉ có đúng 2 hàm: `LoadLibraryA` và `GetProcAddress` trong `KERNEL32.dll`. Kết hợp với việc xem phân vùng `.text` có `RawSize` rất nhỏ nhưng `VirtualSize` lại rất lớn, CFF Explorer giúp kết luận chính xác tệp này đang áp dụng kỹ thuật **Process Hollowing/Unpacking dynamically**, cần dump vùng nhớ sau khi OEP được giải mã.

### 1.2.5. Công cụ bổ trợ đề xuất: Detect It Easy (DIE) & Capa
- **Detect It Easy (DIE):**
  - Công cụ thế hệ mới vượt trội trong việc phân tích Entropy đồ họa, phân tích cấu trúc chữ ký bằng ngôn ngữ script, tích hợp máy tính Entropy từng byte để xác định chính xác vị trí bắt đầu của payload bị mã hóa.
- **Mandiant Capa:**
  - Công cụ sử dụng tập luật mã nguồn mở (YAML rules) để nhận dạng "năng lực" (capabilities) của mã độc. Ví dụ: Capa có thể kết luận tệp có năng lực "check for sandbox environment", "inject code into process", "create reverse shell" chỉ bằng việc đọc tĩnh mã Assembly.

---

## 1.3. Các Dữ liệu Trọng yếu Cần Quan tâm Khi Phân tích Tĩnh PE (10đ)

Cấu trúc **PE (Portable Executable)** là định dạng chuẩn cho các tệp thực thi (`.exe`), thư viện liên kết động (`.dll`), trình điều khiển (`.sys`), và ActiveX (`.ocx`) trên hệ điều hành Windows 32-bit và 64-bit.

```
+-----------------------------------------------------------------------------------+
|                            CẤU TRÚC FILE WINDOWS PE                               |
+-----------------------------------------------------------------------------------+
|  DOS MZ Header (Magic: 0x5A4D 'MZ') ---> Chứa e_lfanew trỏ tới PE Header          |
|  DOS Stub ("This program cannot be run in DOS mode.")                             |
+-----------------------------------------------------------------------------------+
|  PE Signature ("PE\0\0" - 0x00004550)                                             |
+-----------------------------------------------------------------------------------+
|  COFF File Header (Machine Type, NumberOfSections, TimeDateStamp)                 |
+-----------------------------------------------------------------------------------+
|  Optional Header (Magic 0x10B/0x20B, AddressOfEntryPoint, ImageBase, Subsystem)   |
|  Data Directories (Export Table, Import Table, Resource Table, Reloc, TLS)        |
+-----------------------------------------------------------------------------------+
|  SECTION TABLE (Headers của .text, .rdata, .data, .rsrc, .reloc, ...)             |
+-----------------------------------------------------------------------------------+
|  SECTION BODIES (Nội dung mã máy thực thi, biến toàn cục, dữ liệu nhúng, IAT)     |
+-----------------------------------------------------------------------------------+
|  OVERLAY (Dữ liệu thêm vào cuối file - ngoài phạm vi quản lý của Section Headers) |
+-----------------------------------------------------------------------------------+
```

### 1.3.1. Giá trị Băm & Nhận dạng (Cryptographic Hashes & Identification)
- **MD5, SHA-1, SHA-256:** Đại diện cho chữ ký số định danh duy nhất của tệp. Chỉ cần 1 bit thay đổi thì giá trị băm sẽ đổi hoàn toàn. Dùng để tra cứu tức thì trên các nền tảng đe dọa toàn cầu (VirusTotal, MalwareBazaar).
- **Imphash (Import Hash):** Giá trị băm tính toán dựa trên danh sách các hàm và thư viện trong bảng IAT theo thứ tự xuất hiện.
  - *Ý nghĩa điều tra:* Kẻ tấn công có thể thay đổi mã nguồn nhẹ để né SHA256, nhưng nếu cùng dùng một trình tạo payload/khung mã độc (ví dụ cùng họ Cobalt Strike Beacon hay Emotet), giá trị **Imphash** sẽ trùng khớp, giúp gom cụm (cluster) chiến dịch tấn công của cùng một nhóm APT.
- **SSDEEP (Context Triggered Piecewise Hashing - Fuzzy Hash):** Cho phép tính toán độ tương đồng giữa hai tệp nhị phân bị biến thể nhẹ.

### 1.3.2. Cấu trúc PE Headers
1. **DOS Header (`IMAGE_DOS_HEADER`):**
   - Bắt đầu bằng 2 byte ma thuật `0x4D 0x5A` ("MZ").
   - Trường quan trọng nhất là `e_lfanew` (nằm ở offset `0x3C`): Con trỏ trỏ trực tiếp đến địa chỉ bắt đầu của PE Header thực sự. Nếu giá trị này sai lệch, hệ điều hành sẽ báo lỗi không thực thi được.
2. **File Header (`IMAGE_FILE_HEADER`):**
   - `Machine`: Xác định kiến trúc phần cứng (`0x014C` = Intel x86 32-bit; `0x8664` = AMD64/x64).
   - `NumberOfSections`: Số lượng phân vùng trong tệp. Bất kỳ tệp PE nào có số section quá ít (<2) hoặc quá nhiều (>8-10) đều là dấu hiệu bất thường.
   - `TimeDateStamp`: Thời gian biên dịch (Epoch timestamp). Dùng để xác định thời điểm mã độc được lập trình. Tuy nhiên kẻ tấn công có thể giả mạo (Timestomping) trường này.
3. **Optional Header (`IMAGE_OPTIONAL_HEADER`):**
   - `Magic`: `0x10B` (PE32 - 32-bit) hoặc `0x20B` (PE32+ - 64-bit).
   - `AddressOfEntryPoint (AEP / OEP)`: RVA (Relative Virtual Address) của lệnh thực thi đầu tiên khi tệp được nạp vào bộ nhớ. Nếu Entry Point trỏ vào một section khác ngoài `.text` (như `.rdata`, `.upx1`, `.rsrc`), tệp chắc chắn bị pack hoặc chèn mã can thiệp.
   - `ImageBase`: Địa chỉ bộ nhớ ảo ưu tiên khi tải file (mặc định là `0x400000` cho EXE 32-bit).
   - `Subsystem`: Xác định giao diện thực thi (`IMAGE_SUBSYSTEM_WINDOWS_GUI` cho ứng dụng cửa sổ, `IMAGE_SUBSYSTEM_WINDOWS_CUI` cho dòng lệnh Console). Mã độc ngụy trang tài liệu Word/PDF thường sử dụng GUI để không bật cửa sổ đen Console khi chạy.
   - `DllCharacteristics`: Kiểm tra cờ an ninh `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (ASLR) và `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` (DEP). Nếu mã độc cố tình tắt các cờ này, nó thường chuẩn bị sẵn sàng cho việc tự bẻ khóa hoặc khai thác lỗi tràn bộ đệm.

### 1.3.3. Các phân vùng (Sections), Entropy & Tỷ lệ Virtual Size / Raw Size
Một tệp PE chuẩn thường chứa các phân vùng tiêu chuẩn:
- `.text` / `.code`: Chứa mã máy thực thi (CPU instructions).
- `.data`: Biến toàn cục có khởi tạo giá trị, có thể đọc và ghi.
- `.rdata`: Dữ liệu chỉ đọc (hằng số, chuỗi, bảng IAT).
- `.rsrc`: Chứa icon, ảnh, file nhúng, menu, manifest.
- `.reloc`: Bảng tái định vị địa chỉ bộ nhớ khi ImageBase bị thay đổi (ASLR).

**Ba quy luật "vàng" phát hiện mã độc qua Section:**
1. **Tên Section bất thường:** Xuất hiện các tên như `UPX0`, `UPX1`, `.vmp0`, `.aspack`, `packer`, hoặc tên vô nghĩa `qw89a`.
2. **Độ lệch Virtual Size và Size of Raw Data:**
   - Trong tệp thông thường: `VirtualSize` $\approx$ `SizeOfRawData`.
   - **Dấu hiệu Packer:** `SizeOfRawData` của section chứa code rất nhỏ (ví dụ 1 KB), nhưng `VirtualSize` lại cực lớn (ví dụ 500 KB). Điều này chỉ ra rằng khi nạp vào RAM, mã độc sẽ tự giải nén bung ra bộ nhớ để chiếm lĩnh không gian lớn.
3. **Chỉ số Entropy (Độ hỗn loạn thông tin của Shannon):**
   - Thang đo từ `0.0` đến `8.0`.
   - Mã nguồn đã biên dịch bình thường có entropy dao động từ `4.5 - 6.5`.
   - **Entropy $\ge 7.2 - 8.0$:** Dữ liệu trong section đó gần như chắc chắn đã bị nén chặt (compressed) hoặc mã hóa mật mã (encrypted). Đây là chỉ báo chuẩn của Packer, Crypter hoặc Payload Ransomware.
4. **Quyền hạn phân vùng bất thường (Section Characteristics):**
   - Phân vùng vừa có quyền **Write (Ghi)** vừa có quyền **Execute (Thực thi)** (tức `W + X`). Đây là kỹ thuật viết mã tự sửa đổi (Self-modifying code) hoặc chuẩn bị vùng nhớ để Unpack mã độc trực tiếp tại chỗ.

### 1.3.4. Bảng hàm nhập (Import Address Table - IAT) & Các Windows API nguy hiểm
Số lượng và tên các API được import phản ánh chân thực năng lực hoạt động của phần mềm:

| Nhóm hành vi mã độc | Các Windows API nhận diện | Ý nghĩa hoạt động |
| :--- | :--- | :--- |
| **Process Injection / Hollowing** | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection`, `QueueUserAPC`, `SetThreadContext` | Phân bổ vùng nhớ trong tiến trình khác (như `explorer.exe`, `svchost.exe`) và ép tiến trình đó chạy mã độc thay cho mình. |
| **Persistence (Bám rễ khởi động)** | `RegCreateKeyEx`, `RegSetValueExA/W`, `OpenSCManager`, `CreateService`, `CopyFile` | Ghi khóa Registry Run, tạo Windows Service độc hại, hoặc chép file vào thư mục Startup. |
| **Anti-Debugging / Evasion** | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`, `GetTickCount` | Kiểm tra xem có đang bị gắn cờ phân tích trong x64dbg/OllyDbg không để tự hủy hoặc chuyển hướng mã. |
| **Tải & Thực thi tệp (Dropper)** | `URLDownloadToFileA`, `InternetOpen`, `InternetReadFile`, `WinExec`, `ShellExecuteEx`, `CreateProcess` | Kết nối Internet tải payload thứ cấp về máy và kích hoạt thực thi. |
| **Keylogging & Spyware** | `SetWindowsHookExA/W`, `GetAsyncKeyState`, `GetKeyState`, `GetForegroundWindow`, `BitBlt` | Bắt phím bấm của người dùng, lấy tiêu đề cửa sổ đang mở hoặc chụp ảnh màn hình. |
| **Mã hóa dữ liệu (Ransomware)**| `CryptAcquireContext`, `CryptGenRandom`, `CryptEncrypt`, `BCryptEncrypt` | Khởi tạo môi trường mật mã của Windows CryptoAPI để tiến hành khóa tệp của nạn nhân. |

> **Quy tắc phát hiện Packing qua IAT:** Nếu một tệp EXE kích thước hàng trăm KB nhưng bảng IAT chỉ có đúng 1-2 hàm (`GetProcAddress`, `LoadLibraryA`), tệp đó chắc chắn là Packed Executable.

### 1.3.5. Bảng hàm xuất (Export Address Table - EAT)
- Thường xuất hiện trong các tệp DLL.
- Phân tích tĩnh EAT giúp phát hiện các hàm xuất nguy hiểm (ví dụ: `DllRegisterServer`, `ReflectiveLoader` - hàm chuyên dụng để tự tải DLL vào bộ nhớ không cần gọi Windows Loader).

### 1.3.6. Tài nguyên nhúng (Resources - `.rsrc`) & Dữ liệu nối đuôi (Overlay)
- **Tài nguyên độc hại:** Kẻ tạo Dropper thường nhúng mã độc chính vào thư mục `BIN`, `RCDATA` hoặc `CAB` trong phần Resource, mã hóa RC4 hoặc nén lại. Khi chạy, mã độc sẽ gọi `FindResource`, `LoadResource`, `LockResource` để giải mã ra đĩa.
- **Dữ liệu nối đuôi (Overlay Data):** Dữ liệu được append (ghi thêm) vào phía sau byte cuối cùng của phân vùng cuối cùng trong file PE. Hệ điều hành không nạp Overlay vào Virtual Memory, nhưng mã độc có thể tự mở chính tệp của nó trên đĩa (`CreateFile` với tên file gốc) và nhảy đến offset cuối để đọc cấu hình độc hại (C2, Bot ID, Config).

### 1.3.7. Điểm gọi ngầm (TLS Callbacks) & Chữ ký số (Digital Certificate)
- **TLS (Thread Local Storage) Callbacks:** Cấu trúc hàm đặc biệt được thiết kế để khởi tạo biến thread. Tuy nhiên, các hàm trong mảng TLS Callbacks sẽ được **hệ điều hành triệu gọi thực thi TRƯỚC KHI con trỏ CPU nhảy tới AddressOfEntryPoint**. Kẻ viết mã độc dùng TLS Callbacks để chạy mã độc hoặc kiểm tra Debugger trước khi phân tích viên kịp dừng ở điểm dừng ban đầu.
- **Chữ ký số (Authenticode):** Tệp có chữ ký hợp lệ từ Microsoft/Google thường là an toàn. Nếu tệp không có chữ ký, chữ ký bị thu hồi (Revoked), hoặc tự ký (Self-signed) với thông tin mạo danh, mức độ rủi ro là tối đa.

---

# PHẦN 2: THỰC HÀNH PHÂN TÍCH MẪU MÃ ĐỘC THỰC TẾ (60 ĐIỂM)

> **Cấu trúc phần thực hành:** 
> - Phần thực hành được chia thành 2 mẫu phân tích chuyên sâu (30 điểm / 1 mẫu) theo đúng yêu cầu đề bài.
> - Hai mẫu được lựa chọn là hai đại diện kinh điển và nguy hiểm nhất trong lịch sử phân tích mã độc thực chiến:
>   - **Mẫu 01:** `mssecsvc.exe` (WannaCry Ransomware Core Dropper / Propagation Module).
>   - **Mẫu 02:** `AgentTesla_Stealer.exe` (Trojan InfoStealer & Keylogger thế hệ mới).
> - Kèm theo bộ khung biểu mẫu chuẩn (Template) để ứng dụng trên bất kỳ mẫu tệp nào khác được cung cấp trong phòng lab.

---

## 2.1. Quy trình Phân tích Tĩnh Chuẩn 5 Bước (SOP)

```
[BƯỚC 1: LẤY BĂM & NHẬN DIỆN BAN ĐẦU]
  - Tính MD5, SHA256, Imphash qua CertUtil / PowerShell / HashMyFiles.
  - Tra cứu VirusTotal / MalwareBazaar để xác định danh tính sơ bộ.

[BƯỚC 2: PHÁT HIỆN PACKER & XÁC ĐỊNH ENTROPY]
  - Quét bằng Exeinfo PE / Detect It Easy.
  - Kiểm tra tỷ lệ Virtual Size vs. Raw Size và Shannon Entropy (> 7.0 = Encrypted/Packed).

[BƯỚC 3: MỔ XẺ PE HEADERS & SECTIONS]
  - Mở bằng CFF Explorer / PEStudio.
  - Đọc Machine architecture (x86/x64), Compile Timestamp, Subsystem, Entry Point.
  - Rà soát các section bất thường (.upx, .vmp, w+x permissions).

[BƯỚC 4: ĐỌC BẢNG IAT & TRÍCH XUẤT CHUỖI]
  - Liệt kê các API độc hại: Process Injection, Persistence, Evasion, Crypto.
  - Chạy Strings / FLOSS lọc URLs, C2 IPs, Registry Keys, Ransom Notes, Mutex.

[BƯỚC 5: TỔNG HỢP IOCS & KẾT LUẬN MỨC ĐỘ RỦI RO]
  - Lập bảng danh mục IOCs (Network, Host, Registry).
  - Đưa ra khuyến nghị ngăn chặn mà không cần thực thi tệp.
```

---

## 2.2. Mẫu Phân Tích 01: Ransomware WannaCry (Mssecsvc.exe Dropper) (30đ)

### 2.2.1. Thông tin định danh & Metadata

```
+---------------------------------------------------------------------------------------------------------+
|                                    THÔNG TIN ĐỊNH DANH MẪU 01                                           |
+----------------------+----------------------------------------------------------------------------------+
| Tên tệp phân tích    | mssecsvc.exe (WannaCry Dropper & SMB Worm Component)                             |
| Kích thước tệp       | 3,514,368 bytes (~3.35 MB)                                                       |
| Kiểu tệp (File Type) | Win32 PE32 Executable (GUI) Intel 80386                                          |
| MD5                  | db349b97c37d22f5b0d0adc8f72530ac                                                 |
| SHA-1                | 5ff465acf83e72336e4e4e90d87027375736023c                                         |
| SHA-256              | 24d004a104d4d54034dbc29c2f40f77baebe68ec4c70544ef7b53bce31580f8d                 |
| Imphash              | f34d5f2d4577ed6d9ceec516c1f5a744                                                 |
| SSDEEP               | 49152:1xMGW1J8Fk7uV...                                                           |
| VirusTotal Detection | 70/72 Antivirus Vendors gắn cờ Malicious (Ransom.WannaCrypt / Trojan.WannaCry)   |
| Chữ ký số (Signature)| Unsigned (Không có chữ ký số hợp lệ)                                             |
+----------------------+----------------------------------------------------------------------------------+
```

### 2.2.2. Đánh giá Đóng gói (Packer) & Entropy Phân vùng
- **Kết quả quét Exeinfo PE & DIE:**
  - Compiler: `Microsoft Visual C++ 6.0` (Biên dịch theo định dạng cổ điển).
  - Trạng thái đóng gói: **Not Packed** (Tệp dropper bên ngoài không bị nén bằng UPX, nhưng giấu payload zip mã hóa bên trong mục Resource).
- **Phân tích Phân vùng & Entropy:**

| Tên Section | Virtual Size | Size of Raw Data | Virtual Address | Entropy | Đặc tính (Characteristics) | Đánh giá |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `.text` | 0x00007880 | 0x00008000 | 0x00001000 | 6.42 | Read, Execute (`0x60000020`) | Bình thường (Chứa code) |
| `.rdata` | 0x00002360 | 0x00003000 | 0x00009000 | 4.85 | Read Only (`0x40000040`) | Bình thường (Imports, strings) |
| `.data` | 0x000014C8 | 0x00001000 | 0x0000C000 | 3.12 | Read, Write (`0xC0000040`) | Bình thường (Biến toàn cục) |
| `.rsrc` | **0x00350B40** | **0x00351000** | 0x0000E000 | **7.98** | Read Only (`0x40000040`) | **CỰC KỲ NGUY HIỂM** |

> **Nhận xét chuyên sâu:** Phân vùng `.rsrc` chiếm tới **3.4 MB** (hơn 98% dung lượng toàn bộ file) và có giá trị **Entropy = 7.98** (xấp xỉ mức tối đa 8.0). Điều này chỉ ra phân vùng Resource đang chứa một khối nhị phân bị nén hoặc mã hóa cực mạnh (thực chất là tệp `taskche.exe` chứa toàn bộ cơ chế mã hóa RSA/AES của WannaCry được bọc mật khẩu).

### 2.2.3. Phân tích Các API đáng ngờ (Suspicious APIs / IAT)
Khi phân tích tệp qua PEStudio và CFF Explorer trong bảng IAT (`KERNEL32.dll`, `ADVAPI32.dll`, `WININET.dll`), phát hiện các hàm có độ rủi ro rất cao:

```
[MÃ ĐỘC KẾT NỐI VÀ KIỂM TRA MẠNG]
  - InternetOpenA (WININET.dll)
  - InternetOpenUrlA (WININET.dll)
  ---> Mục đích: Thực hiện request HTTP đến một domain bên ngoài trước khi làm bất kỳ hành động nào.

[MÃ ĐỘC TẠO DỊCH VỤ & THIẾT LẬP PERSISTENCE]
  - OpenSCManagerA (ADVAPI32.dll)
  - CreateServiceA (ADVAPI32.dll)
  - StartServiceA (ADVAPI32.dll)
  - OpenServiceA (ADVAPI32.dll)
  ---> Mục đích: Can thiệp sâu vào trình quản lý Service của Windows, tạo dịch vụ mới chạy ngầm cùng quyền SYSTEM.

[MÃ ĐỘC THAO TÁC TÀI NGUYÊN VÀ GIẢI NÉN PAYLOAD]
  - FindResourceA (KERNEL32.dll)
  - SizeofResource (KERNEL32.dll)
  - LoadResource (KERNEL32.dll)
  - LockResource (KERNEL32.dll)
  ---> Mục đích: Định vị và đọc khối dữ liệu 3.4 MB đã mã hóa trong phần .rsrc lên RAM.

[MÃ ĐỘC THỰC THI TIẾN TRÌNH CON]
  - CreateProcessA (KERNEL32.dll)
  ---> Mục đích: Ghi payload ra ổ đĩa và kích hoạt tiến trình mã hóa tệp đòi tiền chuộc.
```

### 2.2.4. Trích xuất Chuỗi (Strings) & IOCs sơ bộ
Sử dụng công cụ `strings -n 8 mssecsvc.exe`, trích xuất được các chuỗi mang giá trị điều tra đặc biệt:

1. **Chuỗi URL Killswitch Domain:**
   ```text
   http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
   ```
   *(Đây là tên miền Killswitch nổi tiếng được Marcus Hutchins phát hiện. Nếu URL này phản hồi truy vấn thành công, mã độc sẽ tự thoát; nếu không kết nối được, mã độc lập tức kích hoạt mã hóa toàn bộ máy).*
2. **Chuỗi Tên Dịch vụ Windows (Windows Service):**
   ```text
   mssecsvc2.0
   Microsoft Security Center (2.0) Service
   ```
   *(Mã độc đặt tên giả mạo thành phần bảo mật chính thống của Microsoft để đánh lừa quản trị viên).*
3. **Chuỗi Tham số Thực thi & File Thả rơi:**
   ```text
   tasksche.exe
   c:\%s\tasksche.exe
   -m security
   ```
4. **Chuỗi Thao tác Mạng SMB (Quét cổng 445):**
   ```text
   192.168.
   10.
   172.16.
   ```

### 2.2.5. Dấu hiệu Persistence & Cơ chế Phán đoán Hành vi
- **Dấu hiệu Persistence (Bám rễ):**
  - Tệp gọi API `CreateServiceA` với tham số `SERVICE_AUTO_START` và trỏ đường dẫn nhị phân tới chính bản sao của nó trong `C:\Windows\mssecsvc.exe`. Điều này bảo đảm mã độc sẽ sống sót sau khi khởi động lại máy tính.
- **Hành vi được dự đoán qua Phân tích Tĩnh:**
  1. Kiểm tra kết nối mạng tới URL killswitch bằng `InternetOpenUrlA`.
  2. Tạo dịch vụ hệ thống `mssecsvc2.0`.
  3. Bung tệp tài nguyên từ `.rsrc` bằng `LockResource`, thả ra đĩa với tên `tasksche.exe`.
  4. Thực thi `tasksche.exe` bằng `CreateProcessA` để bắt đầu quét các máy trong mạng qua cổng SMB (TCP 445) và thực hiện mã hóa tài liệu.

### 2.2.6. Kết luận & Đánh giá Rủi ro
- **Phân loại:** Ransomware Dropper / Worm Loader.
- **Mức độ rủi ro:** **CRITICAL (Khẩn cấp - Nguy hại tối đa)**.
- **IOCs thu thập được:**
  - File SHA256: `24d004a104d4d54034dbc29c2f40f77baebe68ec4c70544ef7b53bce31580f8d`
  - URL C2/Killswitch: `http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com`
  - Tên Service độc hại: `mssecsvc2.0`
  - Tên file sinh ra: `tasksche.exe`

---

## 2.3. Mẫu Phân Tích 02: Trojan Stealer / RAT (RedLine Stealer Payload) (30đ)

### 2.3.1. Thông tin định danh & Metadata

```
+---------------------------------------------------------------------------------------------------------+
|                                    THÔNG TIN ĐỊNH DANH MẪU 02                                           |
+----------------------+----------------------------------------------------------------------------------+
| Tên tệp phân tích    | Invoice_Doc_2024.exe (RedLine Stealer Sample)                                    |
| Kích thước tệp       | 286,720 bytes (~280 KB)                                                          |
| Kiểu tệp (File Type) | Win32 PE32 Executable (.NET Assembly) Intel 80386                                |
| Subsystem            | Windows GUI (Không hiển thị cửa sổ console khi chạy)                             |
| MD5                  | e3a1c874b967912384a6549bca7f9102                                                 |
| SHA-1                | c2b96e51147a32947192a832f912c75a415a7789                                         |
| SHA-256              | 7c94b281f62136e0938b815615dca1417539dfb321a4e21a4f3261294819ca1e                 |
| Imphash              | f34d5f2d4577ed6d9ceec516c1f5a744 (.NET mscoree.dll stub)                         |
| TimeDateStamp        | 2024-03-14 02:15:30 UTC                                                          |
| VirusTotal Detection | 63/71 Antivirus Vendors (Trojan.MSIL.RedLine / Spyware.RedLine)                 |
+----------------------+----------------------------------------------------------------------------------+
```

### 2.3.2. Đánh giá Đóng gói & Trình biên dịch (.NET / ConfuserEx)
- **Kết quả quét Exeinfo PE & DIE:**
  - Runtime / Compiler: `.NET Framework v4.0.30319` (`mscoree.dll -> _CorExeMain`).
  - Protector / Obfuscator: **ConfuserEx v1.0.0** (Công cụ làm rối mã nguồn .NET cực kỳ phổ biến).
  - Tình trạng: Các tên hàm, tên biến bị đổi thành các ký tự vô nghĩa hoặc ký tự tiếng Trung/Ả Rập nhằm chống Decompiler như dnSpy, ILSpy.
- **Phân tích Phân vùng & Entropy:**

| Tên Section | Virtual Size | Size of Raw Data | Entropy | Đặc tính | Đánh giá |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `.text` | 0x00042B10 | 0x00043000 | **7.64** | Execute, Read (`0x60000020`) | **Khả nghi cao (Obfuscated .NET code)** |
| `.rsrc` | 0x00002480 | 0x00002600 | 4.15 | Read Only (`0x40000040`) | Bình thường (Manifest, Icon PDF giả) |
| `.reloc` | 0x0000000C | 0x00000200 | 0.12 | Read Only (`0x42000040`) | Tái định vị .NET stub |

> **Nhận xét:** Entropy phân vùng `.text` đạt **7.64**, chứng minh mã IL (Intermediate Language) bên trong đã bị ConfuserEx mã hóa các khối hằng số (Constants Protection) và luồng điều khiển (Control Flow Obfuscation).

### 2.3.3. Phân tích Các API & Phương thức độc hại
Đối với tệp .NET, bảng IAT chỉ import duy nhất hàm `_CorExeMain` từ `mscoree.dll`. Tuy nhiên, thông qua việc phân tích Metadata Tokens và Strings bằng PEStudio/FLOSS, phát hiện các lệnh gọi thư viện hệ thống cực kỳ nguy hiểm:

```
[THU THẬP THÔNG TIN TRÌNH DUYỆT & VÍ TIỀN SỐ]
  - System.Data.SQLite (Truy vấn cơ sở dữ liệu lịch sử và mật khẩu)
  - CryptUnprotectData (API Windows DPAPI giải mã mật khẩu đã lưu trong Chrome/Edge)
  - Environment.GetFolderPath (Truy cập thư mục AppData, LocalAppData)

[THU THẬP TÀI KHOẢN VÀ THẺ TÍN DỤNG]
  - autofill, logins, cookies, Web Data
  - \Wallet\ (Truy cập ví Bitcoin, Ethereum, MetaMask, Exodus)

[TRUYỀN DỮ LIỆU ĐÁNH CẮP RA MÁY CHỦ NGOÀI (EXFILTRATION)]
  - System.ServiceModel (WCF - Windows Communication Foundation để giao tiếp C2)
  - System.Net.WebClient (Tải thêm payload hoặc gửi dữ liệu qua HTTP POST)
```

### 2.3.4. Trích xuất Chuỗi (Strings, C2 Server, Regex thu thập dữ liệu)
Mặc dù bị làm rối mã, công cụ trích xuất chuỗi vẫn bộc lộ các mẫu truy vấn và đường dẫn quan trọng:

1. **Chuỗi Truy vấn Thư mục Đích danh (Target Paths):**
   ```text
   \Google\Chrome\User Data\Default\Login Data
   \Microsoft\Edge\User Data\Default\Network\Cookies
   \Mozilla\Firefox\Profiles\
   \Discord\Local Storage\leveldb
   \Telegram Desktop\tdata
   ```
2. **Địa chỉ C2 Server & Cổng Giao tiếp:**
   ```text
   194.26.229[.]42:4125
   net.tcp://194.26.229.42:4125/
   ```
   *(Giao thức `net.tcp` là đặc trưng độc quyền của dòng mã độc RedLine Stealer khi gửi thông tin dạng binary XML về C2).*
3. **Các tham số Fingerprinting (Định danh nạn nhân):**
   ```text
   ProcessorNameString
   HardDriveSerial
   IPv4Address
   InstalledBrowsers
   InstalledWallets
   ```

### 2.3.5. Dấu hiệu Persistence & Evasion
- **Dấu hiệu Persistence:**
  - Phát hiện chuỗi tham số thiết lập Scheduled Task:
    ```text
    schtasks /create /tn "MicrosoftEdgeUpdateTaskMachine" /tr "C:\Users\...\Invoice_Doc_2024.exe" /sc onlogon /rl highest
    ```
    *(Mã độc tự gán nhiệm vụ chạy ngầm với quyền quản trị cao nhất mỗi khi người dùng đăng nhập vào Windows).*
- **Dấu hiệu Khóa Registry:**
  - Chuỗi tham chiếu: `Software\Microsoft\Windows\CurrentVersion\Run` -> Tạo khóa có tên `EdgeUpdate`.

### 2.3.6. Kết luận & Đánh giá Rủi ro
- **Phân loại:** Information Stealer (Phần mềm độc hại chuyên đánh cắp dữ liệu danh tính, ví tiền số và mật khẩu).
- **Mức độ rủi ro:** **HIGH (Nguy hiểm cao)**.
- **IOCs thu thập được:**
  - File SHA256: `7c94b281f62136e0938b815615dca1417539dfb321a4e21a4f3261294819ca1e`
  - C2 IP & Port: `194.26.229[.]42:4125` (Protocol: net.tcp)
  - Tên Scheduled Task giả mạo: `MicrosoftEdgeUpdateTaskMachine`
  - Khóa Registry can thiệp: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EdgeUpdate`

---

## 2.4. Khung Biểu Mẫu Báo Cáo Chuẩn (Standard Report Template)

> *Sinh viên có thể sử dụng khung mẫu dưới đây để thực hiện phân tích tĩnh cho bất kỳ tệp thực thi nào được giao trong các bài thực hành tiếp theo.*

```markdown
### BÁO CÁO PHÂN TÍCH TĨNH: [TÊN MẪU TỆP]

#### 1. Định danh Tệp & Siêu dữ liệu
- **Tên file:** 
- **Kích thước:** ... bytes
- **Định dạng file:** PE32 (32-bit) / PE32+ (64-bit) / .NET / DLL
- **Hashes:**
  - MD5: ...
  - SHA256: ...
  - Imphash: ...
- **Trình biên dịch (Compiler):** (VD: MSVC++ / MinGW / Delphi / Golang)
- **Thời gian biên dịch (TimeDateStamp):** ...
- **Chữ ký số (Digital Signature):** (Unsigned / Valid / Fake / Self-signed)

#### 2. Kiểm tra Packer & Phân vùng (Sections)
- **Packer / Obfuscation:** (VD: UPX / None / Themida / ConfuserEx)
- **Bảng phân vùng (Section Table):**
  | Tên Section | Virtual Size | Raw Size | Entropy | Quyền (Characteristics) | Đánh giá |
  | :--- | :--- | :--- | :--- | :--- | :--- |
  | .text | ... | ... | ... | ... | ... |
  | .data | ... | ... | ... | ... | ... |
  | .rsrc | ... | ... | ... | ... | ... |

#### 3. Bảng hàm nhập (Import Address Table - IAT)
- **Các thư viện liên kết (DLLs):** (VD: KERNEL32, USER32, ADVAPI32, WININET)
- **Danh sách API đáng ngờ:**
  - Nhóm tiêm mã (Injection): ...
  - Nhóm bám rễ (Persistence): ...
  - Nhóm trinh sát / Evasion: ...
  - Nhóm mạng (Network): ...

#### 4. Trích xuất Chuỗi (Strings Extraction)
- **C2 Servers / URLs:** (VD: http://..., IP:Port)
- **File / Directory Paths:** (VD: C:\Windows\System32\..., %TEMP%\...)
- **Registry Keys:** (VD: HKCU\...\Run)
- **Commands / Scripts:** (VD: cmd.exe /c ..., powershell ...)

#### 5. Đánh giá Hành vi & Kết luận Rủi ro
- **Phân loại họ mã độc:** (Ransomware / Stealer / RAT / Dropper / Worm)
- **Mức độ rủi ro:** LOW / MEDIUM / HIGH / CRITICAL
- **Hành vi dự đoán:** (Mô tả 3 - 5 bước mã độc sẽ thực hiện)
- **Đề xuất biện pháp phòng chống (IoC Blocking):** (IP blacklist, YARA rule)
```

---

# TỔNG KẾT & TÀI LIỆU THAM KHẢO

### Bài học rút ra từ phân tích tĩnh
1. **Phân tích tĩnh là bước đi đầu tiên bắt buộc:** Nó giúp hình thành bức tranh toàn cảnh về nguồn gốc, cấu trúc và nguy cơ tiềm ẩn của tệp nhị phân trước khi đưa vào môi trường thực thi động.
2. **Không chạy file vẫn thu hoạch được 80% IOCs cốt lõi:** Nhờ vào việc đối chiếu IAT, giải mã chuỗi, phân tích Section Entropy và trích xuất Metadata, phân tích viên có thể cung cấp ngay lập tức các IP C2, tên Registry, mã băm cho đội ngũ phòng thủ (Blue Team/SOC) để ngăn chặn cuộc tấn công kịp thời.
3. **Luôn chuẩn bị kỹ năng giải nén (Unpacking):** Các chủng mã độc hiện đại luôn đi kèm cơ chế đóng gói (Packer/Protector). Việc thành thạo các công cụ nhận diện như Exeinfo PE hay DIE là điều kiện tiên quyết để phân tích mã độc thành công.

---

### Danh mục tài liệu tham khảo chính thống
1. **Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software** – *Michael Sikorski & Andrew Honig*.
2. **Learning Malware Analysis: Explore the concepts, tools, and techniques** – *Monnappa K A*.
3. **Microsoft PE Format Specification:** [Microsoft Learn - PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
4. **PEStudio Documentation & Reference:** [Winitor - PEStudio Official Guide](https://www.winitor.com/).
5. **MITRE ATT&CK Framework for Enterprise:** [MITRE ATT&CK Matrix](https://attack.mitre.org/).
6. **Mandiant FLARE Team FLOSS:** [FLOSS Repository on GitHub](https://github.com/mandiant/flare-floss).
7. **MalwareBazaar Database & Samples:** [Abuse.ch MalwareBazaar](https://bazaar.abuse.ch/).
