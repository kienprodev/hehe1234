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

