# BÁO CÁO PHÂN TÍCH: TÌM HIỂU CÁC LOẠI MÃ ĐỘC PHỔ BIẾN (MALWARE TAXONOMY & MODERN CASE STUDIES)


---

## MỤC LỤC

1. [Phần 1: Khái niệm & Bản chất của Malware](#phần-1-khái-niệm--bản-chất-của-malware)
   - 1.1. Định nghĩa Malware
   - 1.2. Mục đích và động cơ tồn tại
   - 1.3. Phân biệt Malware với các khái niệm liên quan (Bug, Grayware/PUA, Exploit)
2. [Phần 2 & 3: Phân tích 10 nhóm mã độc & Các Case Study mới nhất (2023 - 2024+)](#phần-2--3-phân-tích-10-nhóm-mã-độc--các-case-study-mới-nhất-2023---2024)
   - 2.1. Virus (Mẫu mới: Win32.Neshta)
   - 2.2. Worm (Mẫu mới: Raspberry Robin)
   - 2.3. Trojan (Mẫu mới: Qakbot / Operation Duck Hunt)
   - 2.4. Backdoor / RAT (Mẫu mới: AsyncRAT & Sliver C2)
   - 2.5. Adware (Mẫu mới: Badbox & ViperSoftX)
   - 2.6. Botnet (Mẫu mới: KV-Botnet / Volt Typhoon)
   - 2.7. Ransomware (Mẫu mới: LockBit 3.0 / Operation Cronos)
   - 2.8. Information Stealer (Mẫu mới: Lumma Stealer / LummaC2)
   - 2.9. Rootkit (Mẫu mới: BlackLotus UEFI Bootkit)
   - 2.10. Dropper / Loader (Mẫu mới: GootLoader)
3. [Phần 4: Ma trận so sánh & Nhận diện phân loại cập nhật](#phần-4-ma-trận-so-sánh--nhận-diện-phân-loại-cập-nhật)
4. [Phần 5: Danh mục tài liệu tham khảo chính thống](#phần-5-danh-mục-tài-liệu-tham-khảo-chính-thống)

---

## PHẦN 1: KHÁI NIỆM & BẢN CHẤT CỦA MALWARE (10 điểm)

### 1.1. Định nghĩa Malware
**Malware** (viết tắt của **Malicious Software** - phần mềm độc hại) là thuật ngữ kỹ thuật chỉ bất kỳ mã chương trình, script hoặc phần mềm nào được tạo ra với chủ đích xâm phạm tính bảo mật (**Confidentiality**), tính toàn vẹn (**Integrity**), hoặc tính sẵn sàng (**Availability**) của hệ thống máy tính, mạng hoặc thiết bị của người dùng mà không có sự cho phép.

Theo chuẩn **NIST SP 800-83 Rev. 1**:
> *"Malware is a program that is covertly inserted into another program with the intent to destroy data, run destructive or intrusive programs, or otherwise compromise the confidentiality, integrity, or availability of the victim's data, applications, or operating system."*

### 1.2. Mục đích và động cơ tồn tại
- **Kiếm tiền phi pháp (Cybercrime as a Service - CaaS):** Tống tiền bằng mã hóa dữ liệu (Ransomware-as-a-Service), đánh cắp tài khoản ngân hàng và ví tiền số (Stealer-as-a-Service).
- **Gián điệp mạng quốc gia (Nation-State Espionage / APT):** Thu thập bí mật chính trị, quân sự, cơ sở dữ liệu quốc phòng và sở hữu trí tuệ doanh nghiệp.
- **Phá hoại cơ sở hạ tầng trọng yếu (Wiper / Cyber Sabotage):** Xóa sạch ổ đĩa, làm tê liệt hệ thống điều khiển công nghiệp (SCADA/ICS) và lưới điện viễn thông.
- **Chiếm dụng tài nguyên phân tán:** Sử dụng máy nạn nhân để tạo proxy ẩn danh, gửi email lừa đảo hoặc mở các đợt tấn công từ chối dịch vụ (DDoS) khổng lồ.

### 1.3. Phân biệt Malware với các khái niệm liên quan

| Khái niệm | Định nghĩa kỹ thuật | Ý chí chủ quan | Tác động thực tế |
| :--- | :--- | :--- | :--- |
| **Malware** | Mã độc được lập trình có chủ đích nhằm gây tổn hại cho người dùng hoặc hệ thống. | **Cố ý (Malicious)** | Vi phạm nghiêm trọng bộ ba CIA, bị pháp luật nghiêm cấm. |
| **Software Bug** | Lỗi vô ý trong logic hoặc mã nguồn của phần mềm hợp pháp. | **Vô ý (Unintentional)** | Có thể làm treo ứng dụng hoặc vô tình tạo ra lỗ hổng bảo mật. |
| **Exploit** | Đoạn dữ liệu/lệnh tận dụng Software Bug để ép phần mềm hoạt động trái ý muốn tác giả. | **Công cụ trung gian** | Có thể dùng cho mục đích phòng thủ (Red Team, Vá lỗi) hoặc vũ khí hóa thành phần của Malware. |
| **Grayware / PUA** | Ứng dụng không hẳn độc hại nhưng gây phiền toái, cài lén thanh công cụ, thu thập hành vi duyệt web. | **Lắt léo (Deceptive)** | Người dùng thường bấm đồng ý trong thỏa thuận sử dụng (EULA) do không đọc kỹ. |

---

## PHẦN 2 & 3: PHÂN TÍCH 10 NHÓM MÃ ĐỘC & CÁC CASE STUDY MỚI NHẤT (2023 - 2024+) (70 điểm)

---

### 2.1. VIRUS (Mã độc lây nhiễm tệp)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Là đoạn mã độc **không thể hoạt động độc lập**, bắt buộc phải ký sinh bằng cách chèn (inject) chính nó vào bên trong cấu trúc của một tệp tin hợp pháp khác (tệp PE `.exe`, `.dll`, macro văn bản, hoặc boot sector).
- **Cơ chế lây lan:** Cần hành động kích hoạt từ con người. Khi người dùng mở tệp bị lây nhiễm, mã virus sẽ được thực thi trước để tìm kiếm các tệp khác trên hệ thống và lây lan chéo.

#### B. Mẫu thực tế mới: Win32.Neshta
- **Tên mẫu:** Win32.Neshta (vẫn liên tục ghi nhận hoạt động bùng phát trong các chiến dịch 2023 - 2024).
- **Nguồn phân tích uy tín:** [BlackBerry Threat Intelligence: Neshta File Infector Resurgence](https://blogs.blackberry.com), [Mandiant Threat Research](https://www.mandiant.com).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Cơ chế lây nhiễm tệp (PE Appending & Prepending):**
  - Neshta quét toàn bộ các ổ đĩa `C:\`, `D:\`, tìm các file thực thi `.exe` có dung lượng chuẩn.
  - Mã độc đọc 41.472 byte đầu tiên của file nạn nhân, mã hóa chúng rồi gắn vào cuối file. Sau đó, nó ghi đè chính thân mã độc Neshta vào đầu file thực thi.
- **Can thiệp thực thi hệ thống:**
  - Sửa đổi Registry key: `HKCR\exefile\shell\open\command` trỏ về file `svchost.com` độc hại nằm trong thư mục `%Windows%`. Khi bất kỳ file `.exe` nào được người dùng bấm chạy, virus sẽ luôn là thành phần được kích hoạt đầu tiên.
- **Căn cứ phân loại là Virus:** Khả năng biến đổi cấu trúc nhị phân của các file thực thi sạch sẵn có trên máy thành vật chủ mang mầm bệnh.

---

### 2.2. WORM (Sâu máy tính)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Chương trình mã độc **hoàn toàn độc lập (Standalone)**, không cần bám vào file vật chủ.
- **Cơ chế lây lan:** **Tự động quét mạng và nhân bản (Self-propagating)** mà không cần bất kỳ sự tương tác nào của người dùng. Sử dụng các giao thức mạng (SMB, SSH, RPC) hoặc thiết bị ngoại vi để tự lây lan hàng loạt.

#### B. Mẫu thực tế mới: Raspberry Robin (QNAP / USB Worm)
- **Tên mẫu:** Raspberry Robin (được phân tích sâu bởi Microsoft, Trend Micro và CISA giai đoạn 2022 - 2024).
- **Nguồn phân tích uy tín:** [Microsoft Defender Threat Intelligence: Raspberry Robin](https://www.microsoft.com/security/blog), [Trend Micro Research on Raspberry Robin Evolution](https://www.trendmicro.com).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Cơ chế tự lây lan (Propagation Vector):**
  - Lây nhiễm tự động qua USB thông qua các file shortcut `.LNK` trỏ tới lệnh thực thi `cmd.exe /R` để đọc dữ liệu từ tệp nhị phân giả mạo nằm trên thư mục ẩn của USB.
  - Khi đã xâm nhập vào một máy tính trong mạng nội bộ, Raspberry Robin tiếp tục sử dụng các cơ chế tự lây lan sang các máy ngang hàng qua kết nối mạng và thiết bị lưu trữ chia sẻ.
- **Hành vi kỹ thuật:**
  - Sử dụng các tiến trình hệ thống hợp pháp của Windows (Living off the Land Binaries - LoLBins) như `msiexec.exe`, `rundll32.exe`, `fodhelper.exe` để vượt qua kiểm soát UAC và kết nối C2 qua mạng máy chủ TOR.
  - Đóng vai trò bàn đạp lây nhiễm cho các băng đảng Ransomware nguy hiểm như Clop, LockBit.
- **Căn cứ phân loại là Worm:** Khả năng tự lây lan và nhân bản liên tục giữa các thiết bị ngoại vi và mạng máy tính mà không phụ thuộc vào một file phần mềm vật chủ cụ thể nào.

---

### 2.3. TROJAN (Ngựa thành Troy)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Phần mềm độc hại đội lốt một ứng dụng hữu ích, hợp pháp (phần mềm bẻ khóa, bản cập nhật hệ điều hành, file PDF hóa đơn kinh doanh).
- **Cơ chế lây lan:** Dựa vào kỹ thuật lừa đảo tâm lý (**Social Engineering**) để người dùng tự tay tải về và cài đặt. Không có cơ chế tự nhân bản.

#### B. Mẫu thực tế mới: Qakbot (QBot) & Chiến dịch triệt phá "Operation Duck Hunt" (2023)
- **Tên mẫu:** Qakbot (Pinkslipbot).
- **Nguồn phân tích uy tín:** [Bộ Tư pháp Hoa Kỳ (DOJ) & FBI Press Release: Operation Duck Hunt Disruption of Qakbot](https://www.justice.gov), [CISA Advisory: Qakbot Malware](https://www.cisa.gov).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Vỏ bọc ngụy trang tinh vi:**
  - Sử dụng kỹ thuật "Thread Hijacking": Kẻ tấn công xâm nhập vào chuỗi trao đổi email có thật của nạn nhân, trả lời bằng một email giả mạo kèm theo tệp đính kèm nén `.zip` chứa file `.OneNote`, `.PDF` hoặc `.ISO` giả dạng hóa đơn đối tác.
- **Hành vi lén lút:**
  - Khi nạn nhân mở file, mã thực thi PowerShell/VBScript ngầm trích xuất một file DLL độc hại và tiêm (inject) vào tiến trình `at.exe`, `wermgr.exe` hoặc `explorer.exe`.
  - Mở cổng hậu cho phép cài cắm thêm mã độc tống tiền (BlackBasta, Conti).
- **Căn cứ phân loại là Trojan:** Toàn bộ quá trình xâm nhập ban đầu dựa trên sự giả mạo danh tính và đánh lừa người dùng; không tự lây lan lên các file khác trên đĩa cứng.

---

### 2.4. BACKDOOR / RAT (Cửa hậu / Công cụ điều khiển từ xa bí mật)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Mã độc bí mật thiết lập cổng giao tiếp từ xa, vượt qua cơ chế xác thực của hệ thống, trao cho kẻ tấn công quyền kiểm soát máy tính nạn nhân theo thời gian thực (Remote Access Trojan - RAT).
- **Cơ chế liên lạc:** Sử dụng **Reverse Connection** (máy nạn nhân tự kết nối ra máy chủ C2) để vượt qua NAT và Firewall.

#### B. Mẫu thực tế mới: AsyncRAT & Sliver C2
- **Tên mẫu:** AsyncRAT (Mã nguồn mở nhưng bị vũ khí hóa phổ biến nhất trong các cuộc tấn công 2023 - 2024).
- **Nguồn phân tích uy tín:** [CISA & US-CERT Alert on Living off the Land and RAT Tools](https://www.cisa.gov), [Morphisec: AsyncRAT Campaign Breakdown](https://www.morphisec.com).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Hành vi kiểm soát toàn diện:**
  - Duy trì kết nối C2 được mã hóa bằng thuật toán AES/TLS.
  - Tích hợp module theo dõi người dùng: Ghi lại từng thao tác bàn phím (Keylogger), chụp ảnh màn hình liên tục, kích hoạt microphone và camera.
  - Cho phép kẻ tấn công mở Terminal/PowerShell từ xa, duyệt cây thư mục, tải xuống bất kỳ tệp dữ liệu nào từ máy nạn nhân.
- **Căn cứ phân loại là Backdoor/RAT:** Chức năng trọng tâm là cung cấp giao diện tương tác và thực thi lệnh hai chiều theo thời gian thực cho kẻ điều hành từ xa.

---

### 2.5. ADWARE (Mã độc quảng cáo thế hệ mới)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Phần mềm hiển thị quảng cáo cưỡng bức, chuyển hướng lưu lượng duyệt web, đánh tráo kết quả tìm kiếm và âm thầm theo dõi sở thích trực tuyến của người dùng để trục lợi bất chính.
- **Đặc điểm hiện đại:** Không chỉ là các pop-up đơn giản như trước, Adware hiện đại tích hợp khả năng chiếm quyền trình duyệt (Browser Hijacker) và đánh cắp thông tin giao dịch trực tuyến.

#### B. Mẫu thực tế mới: ViperSoftX & Badbox (2023 - 2024)
- **Tên mẫu:** ViperSoftX (Adware lai Stealer) & Chiến dịch Badbox (nhiễm hàng triệu TV Box Android toàn cầu).
- **Nguồn phân tích uy tín:** [Avast Threat Intelligence: ViperSoftX Analysis](https://decoded.avast.io), [HUMAN Security: The Badbox & Peach Pit Fraud Operation](https://www.humansecurity.com).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Hành vi thao túng quảng cáo:**
  - Núp bóng trong các bản bẻ khóa game hoặc ứng dụng tiện ích.
  - Cài tiện ích độc hại (Malicious Extension) vào Google Chrome, Microsoft Edge có tên giả mạo như "VenomSoftX".
  - Khi người dùng lướt web, extension này sẽ tự động chèn banner quảng cáo vào mọi website, thay thế các liên kết tiếp thị (affiliate links) bằng tài khoản của kẻ tấn công, đồng thời đánh tráo địa chỉ ví tiền điện tử trên bộ nhớ tạm (Clipboard Hijacker).
- **Căn cứ phân loại là Adware:** Động cơ vận hành cốt lõi là kiếm tiền từ quảng cáo gian lận (Click Fraud) và chuyển hướng lưu lượng web phi pháp.

---

### 2.6. BOTNET (Mạng máy tính ma)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Mạng lưới gồm hàng ngàn hoặc hàng triệu thiết bị điện toán (máy chủ, PC, camera IoT, router gia đình) bị chiếm quyền điều khiển và đồng bộ hóa mệnh lệnh từ các máy chủ chỉ huy (C2 Server).
- **Mục đích:** Tấn công DDoS với lưu lượng Terabit, tạo mạng lưới proxy chuyển tiếp (Bulletproof Proxy), dò quét mật khẩu phân tán.

#### B. Mẫu thực tế mới: KV-Botnet (Mạng Botnet của nhóm Volt Typhoon - 2023/2024)
- **Tên mẫu:** KV-Botnet.
- **Nguồn phân tích uy tín:** [Lumen Black Lotus Labs: KV-botnet Alert](https://blog.lumen.com/routers-under-attack-kv-botnet), [CISA Advisory: PRC State-Sponsored Actors (Volt Typhoon)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Chiến dịch thâm nhập và điều khiển:**
  - Khai thác các lỗ hổng Zero-day trên thiết bị tường lửa và router SOHO (Cisco RV series, Netgear, DrayTek, Fortinet).
  - Triệt tiêu các tiến trình đối thủ trên thiết bị, cài cắm payload nhị phân trong bộ nhớ RAM để tránh để lại dấu vết trên bộ nhớ flash (In-memory execution).
  - Nhận lệnh từ C2 để biến thiết bị thành một node trong mạng proxy ngầm, phục vụ cho các đợt gián điệp vào mạng lưới hạ tầng trọng yếu (điện lực, đường sắt, viễn thông) của Mỹ mà không bị phát hiện nguồn gốc IP.
- **Căn cứ phân loại là Botnet:** Hoạt động như một cấu trúc mạng lưới phân tán gồm các thiết bị bị xâm nhập, phối hợp thực hiện nhiệm vụ chung dưới sự điều khiển từ xa.

---

### 2.7. RANSOMWARE (Mã độc tống tiền)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Mã độc mã hóa dữ liệu người dùng bằng các thuật toán mã hóa mạnh không thể bẻ gãy, tước đoạt quyền tiếp cận hệ thống và đòi tiền chuộc (thường là Bitcoin, Monero).
- **Chiến thuật tống tiền đa tầng (Multi-extortion):**
  - *Tầng 1:* Mã hóa toàn bộ dữ liệu trên máy chủ và máy trạm.
  - *Tầng 2:* Trích xuất dữ liệu ra ngoài và dọa rò rỉ lên Data Leak Site nếu không trả tiền.
  - *Tầng 3:* Tấn công DDoS vào website của doanh nghiệp nạn nhân để gây áp lực.

#### B. Mẫu thực tế mới: LockBit 3.0 (LockBit Black) & Chiến dịch "Operation Cronos" (2024)
- **Tên mẫu:** LockBit 3.0.
- **Nguồn phân tích uy tín:** [NCA (National Crime Agency UK) & FBI: LockBit Takedown - Operation Cronos](https://nationalcrimeagency.gov.uk), [CISA Alert: Understanding LockBit 3.0](https://www.cisa.gov).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Cơ chế phá hoại dữ liệu:**
  - Sử dụng thuật toán mã hóa lai: Khóa phiên đối xứng mã hóa tệp siêu tốc, kết hợp khóa bất đối xứng RSA/ECC để khóa chìa giải mã.
  - Chạy lệnh ngầm: Xóa Volume Shadow Copies, vô hiệu hóa Windows Event Logs và tắt toàn bộ dịch vụ bảo mật (Windows Defender, EDR).
  - Đổi hình nền màn hình thành thông điệp tống tiền, để lại file `[id].README.txt` hướng dẫn truy cập trang web ẩn danh trên mạng TOR để nộp tiền chuộc.
- **Căn cứ phân loại là Ransomware:** Hành vi tước đoạt quyền tiếp cận dữ liệu và cưỡng đoạt tài chính có cấu trúc.

---

### 2.8. INFORMATION STEALER (Mã độc đánh cắp thông tin định danh)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Phần mềm được tối ưu hóa đặc biệt cho mục tiêu tìm kiếm, giải mã và trích xuất thông tin định danh cá nhân, dữ liệu tài chính của nạn nhân trong thời gian ngắn nhất rồi tẩu tán ra ngoài.
- **Mục tiêu ưu tiên:** Mật khẩu lưu trong trình duyệt, Cookie phiên đăng nhập (Session Cookies), Khóa cá nhân ví tiền số (MetaMask, Trust Wallet), token xác thực Telegram, Discord.

#### B. Mẫu thực tế mới: Lumma Stealer (LummaC2 - 2023 / 2024)
- **Tên mẫu:** Lumma Stealer.
- **Nguồn phân tích uy tín:** [Outpost24 Threat Intelligence: In-depth analysis of LummaC2 Stealer](https://outpost24.com), [Mandiant Threat Research: Modern Infostealers](https://www.mandiant.com).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Thu thập dữ liệu nhắm mục tiêu:**
  - Viết bằng ngôn ngữ C, kích thước cực nhẹ, sử dụng kỹ thuật làm rối mã nguồn cao cấp (Control Flow Flattening).
  - Tự động định vị các đường dẫn cơ sở dữ liệu của các trình duyệt nhân Chromium/Gecko, gọi hàm giải mã DPAPI của Windows để lấy mật khẩu dạng plain-text.
  - Quét tìm hơn 80 loại tiện ích mở rộng ví điện tử và các ứng dụng nhắn tin để đánh cắp Token xác thực 2 bước (2FA Session hijacking).
  - Nén toàn bộ dữ liệu thành file `.zip`, gửi về C2 server qua HTTP POST với Header giả lập lưu lượng duyệt web hợp pháp.
- **Căn cứ phân loại là Stealer:** Hành vi chỉ tập trung vào việc âm thầm vét cạn thông tin định danh và gửi ra ngoài; không phá hoại hệ thống hay tống tiền nạn nhân.

---

### 2.9. ROOTKIT (Mã độc ẩn mình tầng sâu)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Bộ công cụ kỹ thuật can thiệp sâu vào các tầng đặc quyền cao nhất của hệ điều hành (Kernel - Ring 0, Firmware, UEFI) nhằm mục đích tối thượng: **Che giấu sự tồn tại** của chính nó và các mã độc khác trước mọi công cụ Antivirus và EDR.
- **Cơ chế tàng hình:** Sửa đổi bảng gọi hệ thống, can thiệp các cấu trúc dữ liệu nội bộ của nhân hệ điều hành, làm cho tiến trình độc hại trở nên vô hình đối với Task Manager và phần mềm bảo vệ.

#### B. Mẫu thực tế mới: BlackLotus UEFI Bootkit (2023 - 2024)
- **Tên mẫu:** BlackLotus.
- **Nguồn phân tích uy tín:** [ESET Research: BlackLotus UEFI bootkit myth becomes reality](https://www.welivesecurity.com), [Microsoft Security Response Center (MSRC) Guidance on BlackLotus](https://msrc.microsoft.com).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Can thiệp tầng khởi động (Pre-OS Execution):**
  - Là mã độc đầu tiên trên thế giới có khả năng vượt qua hoàn toàn cơ chế bảo mật **UEFI Secure Boot** trên hệ điều hành Windows 11 bằng cách khai thác lỗ hổng `CVE-2022-21894` (Baton Drop).
  - Chạy ngay cả trước khi nhân Windows (Windows Kernel) được nạp vào bộ nhớ.
  - Vô hiệu hóa tính năng bảo vệ dựa trên ảo hóa của Microsoft (Hypervisor-Protected Code Integrity - HVCI), vô hiệu hóa BitLocker và Windows Defender ngay từ cấp phần cứng.
- **Căn cứ phân loại là Rootkit / Bootkit:** Hoạt động dưới tầng nhân hệ thống để thiết lập cơ chế ẩn mình và miễn nhiễm với các công cụ quét mã độc truyền thống trong hệ điều hành.

---

### 2.10. DROPPER / LOADER (Mã độc thả tải trọng thế hệ 2)

#### A. Phân tích đặc điểm cốt lõi
- **Bản chất:** Mã độc đóng vai trò là "ngựa kéo" hoặc "vỏ bọc vận chuyển" (Stage 1), chứa bên trong thân tệp payload độc hại chính được mã hóa hoặc phân mảnh.
- **Nhiệm vụ duy nhất:** Đột nhập vào hệ thống, giải mã payload trong bộ nhớ hoặc ghi tạm ra đĩa, sau đó kích hoạt payload chạy mà không bị các phần mềm quét file tĩnh phát hiện.

#### B. Mẫu thực tế mới: GootLoader (2023 - 2024)
- **Tên mẫu:** GootLoader.
- **Nguồn phân tích uy tín:** [BlackBerry Threat Intelligence: GootLoader Technical Breakdown](https://blogs.blackberry.com), [Mandiant Threat Intelligence](https://www.mandiant.com).

#### C. Phân tích hành vi & Căn cứ kỹ thuật phân loại
- **Phương thức tiếp cận và giải phóng payload:**
  - Sử dụng kỹ thuật ngộ độc công cụ tìm kiếm (SEO Poisoning) để đưa các website giả mạo chứa văn bản mẫu, hợp đồng kinh doanh lên top kết quả Google.
  - Nạn nhân tải về một file `.zip` chứa file JavaScript độc hại. File này được làm rối qua hàng ngàn dòng code vô hại để đánh lừa AV.
  - Khi thực thi, GootLoader chạy ngầm trên bộ nhớ, giải mã nhị phân payload thế hệ 2 (thường là Cobalt Strike, SystemBC, hoặc GootKit) rồi tiêm thẳng vào tiến trình sạch `dllhost.exe` mà không ghi file nhị phân độc hại xuống đĩa cứng (Fileless execution).
- **Căn cứ phân loại là Dropper/Loader:** Bản thân không trực tiếp thực hiện hành vi trộm cắp hay tống tiền; chỉ chuyên chở, ngụy trang và kích hoạt các mã độc nguy hiểm khác.

---

## PHẦN 4: MA TRẬN SO SÁNH & NHẬN DIỆN PHÂN LOẠI CẬP NHẬT

| Nhóm Mã Độc | Tính Độc Lập | Cơ Chế Tự Nhân Bản | Phương Thức Xâm Nhập Phổ Biến Hiện Nay | Mục Tiêu Tác Động | Dấu Hiệu Kỹ Thuật Đặc Trưng |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Virus** | Phụ thuộc (Cần Host File) | Có | Chèn mã vào file PE sạch, chia sẻ file nội bộ | Lây nhiễm file, phá hủy hệ thống | Sửa PE Header, chiếm quyền `exefile\shell\open\command` |
| **Worm** | Độc lập | Có (Rất mạnh mẽ) | Tự quét mạng LAN/SMB, thiết bị lưu trữ USB | Tự nhân bản, chiếm dụng hạ tầng | Lưu lượng quét mạng bất thường, file `.LNK` độc trên USB |
| **Trojan** | Độc lập | Không | Email Thread Hijacking, file giả mạo văn bản | Tạo chỗ đứng bí mật ban đầu | Biểu tượng/tên file đánh lừa, gọi script PowerShell/VBS ngầm |
| **Backdoor/RAT**| Độc lập | Không | Thả bởi Trojan/Dropper | Trao quyền điều khiển từ xa thời gian thực | Kết nối Reverse Shell liên tục ra C2 Server, hook webcam/bàn phím |
| **Adware** | Độc lập/Extension | Không | Kèm trong phần mềm bẻ khóa, lừa click link | Kiếm tiền quảng cáo gian lận | Cài extension lạ vào Browser, đổi search engine, chèn ad script |
| **Botnet** | Độc lập (Kiến trúc mạng) | Thường có | Khai thác lỗ hổng thiết bị mạng/IoT, brute-force | Tấn công DDoS, mạng lưới Proxy ngầm | Thiết bị chạy tiến trình lạ trong RAM, nhận lệnh đồng loạt qua C2 |
| **Ransomware** | Độc lập | Tùy biến | Phishing, RDP Compromise, Dropper | Tống tiền thông qua mật mã học | File bị đổi đuôi, gọi API mã hóa hàng loạt, xóa Volume Shadow Copies |
| **Stealer** | Độc lập | Không | Quảng cáo giả mạo (Malvertising), link tải bẻ khóa | Đánh cắp danh tính, Cookie, ví Crypto | Đọc file SQLite của browser, gọi API DPAPI, nén file zip gửi HTTP POST |
| **Rootkit** | Cấp Driver/Firmware | Không | Khai thác lỗ hổng cấp Kernel (BYOVD), UEFI | Che giấu mã độc, vô hiệu hóa AV/EDR | Can thiệp trước khi OS khởi động (Pre-OS), hook SSDT/DKOM |
| **Dropper** | Độc lập | Không | Tải từ website SEO Poisoning, tệp đính kèm | Thả và kích hoạt payload thế hệ 2 | Chứa mã hóa nhị phân trong tệp, tiêm tiến trình (Process Injection) |

---

## PHẦN 5: DANH MỤC TÀI LIỆU THAM KHẢO CHÍNH THỐNG

1. **NIST SP 800-83 Rev. 1:** *Guide to Malware Incident Prevention and Handling for Desktops and Laptops.* National Institute of Standards and Technology.
2. **CISA & FBI Cybersecurity Advisories (2023 - 2024):**
   - Advisory AA24-038a: *PRC State-Sponsored Actors (Volt Typhoon) Compromise SOHO Routers.*
   - Operation Duck Hunt: *Multinational Action to Disrupt Qakbot Botnet.*
   - Operation Cronos: *Disruption of LockBit Ransomware Group.*
3. **Microsoft Defender Threat Intelligence Research (2023 - 2024):**
   - *Raspberry Robin worm continues to evolve and deploy high-profile payloads.*
   - *Guidance for investigating attacks using the BlackLotus UEFI bootkit.*
4. **Mandiant (Google Cloud) Threat Intelligence:**
   - *M-Trends 2024 Report: In-depth metrics on modern Infostealers and Ransomware tactics.*
5. **ESET Research Whitepapers:**
   - *BlackLotus UEFI Bootkit: Bypassing Secure Boot.*
6. **BlackBerry & Outpost24 Threat Research:**
   - *Technical Reports on GootLoader, Neshta, and LummaC2 Architecture.*
