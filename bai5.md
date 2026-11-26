
# I. Lý thuyết (20 điểm)

## 1. WinAPI là gì?

**WinAPI (Windows Application Programming Interface)** là tập hợp
các giao diện lập trình do Microsoft cung cấp, cho phép các ứng dụng
tương tác với hệ điều hành Windows và sử dụng những tài nguyên do
hệ điều hành quản lý.

## 2. Chức năng của WinAPI trong lập trình Windows

| Chức năng | Các hàm WinAPI tiêu biểu |
|---|---|
| Quản lý file | `CreateFile`, `ReadFile` |
| Quản lý tiến trình | `CreateProcess` |
| Quản lý bộ nhớ | `VirtualAlloc`, `VirtualFree` |
| Quản lý luồng | `CreateThread` |
| Nhập xuất console | `ReadConsole`, `WriteConsole` |
| Giao diện đồ họa | `CreateWindowEx`, `MessageBox` |
| Quản lý Registry | `RegOpenKeyEx`, `RegSetValueEx` |

## 3. Năm WinAPI thường được mã độc sử dụng

### 3.1. VirtualAlloc

- **Chức năng:** Cấp phát vùng nhớ ảo trong không gian địa chỉ
  của tiến trình hiện tại.
- **Ứng dụng trong mã độc:** Có thể được sử dụng để lưu trữ
  mã và dữ liệu độc hại trong bộ nhớ.

### 3.2. WriteProcessMemory

- **Chức năng:** Ghi dữ liệu vào vùng nhớ của một tiến trình
  khi có quyền truy cập phù hợp.
- **Ứng dụng trong mã độc:** Có thể được sử dụng để can thiệp
  hoặc thay đổi dữ liệu trong bộ nhớ của tiến trình khác.

### 3.3. CreateRemoteThread

- **Chức năng:** Tạo một luồng thực thi trong không gian
  địa chỉ của tiến trình khác.
- **Ứng dụng trong mã độc:** Có thể được lợi dụng để thực thi
  mã trong không gian địa chỉ của tiến trình khác.

### 3.4. RegSetValueEx

- **Chức năng:** Tạo hoặc thay đổi giá trị trong Windows Registry.
- **Ứng dụng trong mã độc:** Có thể được sử dụng để thay đổi
  cấu hình hệ thống hoặc duy trì khả năng hoạt động của mã độc
  sau khi máy tính khởi động lại.

### 3.5. IsDebuggerPresent

- **Chức năng:** Kiểm tra tiến trình hiện tại có đang được
  gỡ lỗi bằng debugger hay không.
- **Ứng dụng trong mã độc:** Có thể được sử dụng để phát hiện
  môi trường gỡ lỗi và phân tích mã độc.

## 4. Thực hành

```
#include<windows.h>
HANDLE hInput;
HANDLE hOutput;
void Print(const char* text)

{
	DWORD written;
	WriteConsoleA(
		hOutput,
		text,
		lstrlenA(text),
		&written,
		NULL
	);	

}
int main() {
	hInput = GetStdHandle(STD_INPUT_HANDLE);
	hOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	char filepath[1024];
	DWORD charsRead = 0;
	DWORD bytesRead = 0;
	DWORD written = 0;
	Print("maldev by kiz");
	if (IsDebuggerPresent()) {
		Print("[warn] debugger detected.\n");
	}
	else {
		Print("nothing can stop you\n");
	}
	Print("[input] enter file path:\n ");
	if (!ReadConsoleA( 
		hInput,
			filepath,
			sizeof(filepath) - 1,
			& charsRead,
			NULL
			)){
		Print("Please try again !\n");
			return 1;
	}
	while (charsRead > 0 && (filepath[charsRead
		- 1] == '\r' || filepath[charsRead - 1] == '\n')) {
		charsRead--;
	}
	filepath[charsRead] = '\0';
	HANDLE hfile = CreateFileA(
		filepath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL

	);
	if (hfile == INVALID_HANDLE_VALUE) {
		Print("cannot open file\n");
		return 1;
	}
	Print("[ok] file opened successfully. \n");

	char* buffer = (char*)VirtualAlloc(
		NULL,
		101,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (buffer == NULL) {
		Print("[eror] memory allocation failed.\n");
		CloseHandle(hfile);
		return 1;
	}
	Print("[ôk] memory allocated .\n");
	if (!ReadFile(
		hfile,
		buffer,
		100,
		&bytesRead,
		NULL
	)) {
		Print("[ERROR] Cannot read file .\n");
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hfile);
		return 1;
		buffer[bytesRead] = '\0';
		Print("[ok] File read successfully .\n");
		WriteConsoleA(
			hOutput,
			buffer,
			bytesRead,
			&written,
			NULL
		);
		MessageBoxA(
			NULL,
			buffer,
			"mã độc này vô hại",
			MB_OK | MB_ICONWARNING
		);
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hfile);
		Print("done");
		Print("program end !");
		return 0;
	}
}
```
