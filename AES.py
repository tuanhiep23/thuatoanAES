from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

def aes_encrypt(key, plaintext_data):
    """
    Mã hóa dữ liệu bằng AES-256 ở chế độ CFB (Cipher Feedback).
    Sử dụng IV (Initialization Vector) ngẫu nhiên để tăng cường bảo mật.

    Args:
        key (bytes): Khóa mã hóa (phải có độ dài 32 bytes cho AES-256).
        plaintext_data (bytes): Dữ liệu cần mã hóa.

    Returns:
        bytes: Dữ liệu đã mã hóa (bao gồm IV ở đầu).
    """
    if len(key) != 32: # 256 bits = 32 bytes
        raise ValueError("Khóa phải có độ dài 32 bytes (256 bit) cho AES-256.")

    # Tạo một IV (Initialization Vector) ngẫu nhiên.
    # IV cần duy nhất cho mỗi lần mã hóa, nhưng không cần bí mật.
    iv = get_random_bytes(AES.block_size) # AES.block_size thường là 16 bytes

    cipher = AES.new(key, AES.MODE_CFB, iv)

    # Dữ liệu plaintext không cần đệm với chế độ CFB,
    # nhưng tôi vẫn sử dụng pad để minh họa, mặc dù không cần thiết ở đây.
    # Với CFB, dữ liệu được mã hóa từng bit hoặc byte, giống như một stream cipher.
    # Tuy nhiên, nếu bạn dùng ECB/CBC, pad là rất quan trọng.
    padded_plaintext = pad(plaintext_data, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    # Trả về IV + ciphertext để có thể giải mã sau này
    return iv + ciphertext

def aes_decrypt(key, encrypted_data):
    """
    Giải mã dữ liệu bằng AES-256 ở chế độ CFB.

    Args:
        key (bytes): Khóa giải mã (phải có độ dài 32 bytes).
        encrypted_data (bytes): Dữ liệu đã mã hóa (bao gồm IV ở đầu).

    Returns:
        bytes: Dữ liệu đã giải mã.
    """
    if len(key) != 32:
        raise ValueError("Khóa phải có độ dài 32 bytes (256 bit) cho AES-256.")

    # Trích xuất IV từ đầu dữ liệu mã hóa
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_padded_data = cipher.decrypt(ciphertext)

    # Bỏ đệm dữ liệu sau khi giải mã
    plaintext_data = unpad(decrypted_padded_data, AES.block_size)
    return plaintext_data

if __name__ == "__main__":
    # --- Ví dụ sử dụng ---
    # 1. Tạo một khóa ngẫu nhiên (hoặc dùng khóa cố định 32 bytes)
    # Trong thực tế, khóa cần được lưu trữ/quản lý an toàn
    key = get_random_bytes(32) # Khóa 256-bit (32 bytes)
    print(f"Khóa (hex): {key.hex()}")

    # 2. Dữ liệu văn bản cần mã hóa
    original_text = "Đây là một thông điệp bí mật cần được bảo vệ bằng AES!"
    original_bytes = original_text.encode('utf-8')
    print(f"Dữ liệu gốc: {original_text}")

    # 3. Mã hóa
    encrypted_bytes = aes_encrypt(key, original_bytes)
    print(f"Dữ liệu đã mã hóa (hex): {encrypted_bytes.hex()}")

    # 4. Giải mã
    decrypted_bytes = aes_decrypt(key, encrypted_bytes)
    decrypted_text = decrypted_bytes.decode('utf-8')
    print(f"Dữ liệu đã giải mã: {decrypted_text}")

    # 5. Kiểm tra tính đúng đắn
    assert original_text == decrypted_text
    print("\nMã hóa và giải mã thành công!")

    # --- Mã hóa/Giải mã file ---
    # Tạo một file test
    with open("test_file.txt", "w", encoding="utf-8") as f:
        f.write("Đây là nội dung của file test.\n")
        f.write("Nó có thể chứa nhiều dòng và ký tự đặc biệt.\n")
        f.write("Hãy thử mã hóa và giải mã file này.")

    print("\n--- Mã hóa và giải mã file ---")
    try:
        # Đọc file để mã hóa
        with open("test_file.txt", "rb") as f:
            file_data = f.read()

        # Mã hóa file
        encrypted_file_data = aes_encrypt(key, file_data)
        with open("encrypted_test_file.aes", "wb") as f:
            f.write(encrypted_file_data)
        print("File 'test_file.txt' đã được mã hóa thành 'encrypted_test_file.aes'")

        # Giải mã file
        with open("encrypted_test_file.aes", "rb") as f:
            read_encrypted_data = f.read()
        
        decrypted_file_data = aes_decrypt(key, read_encrypted_data)
        with open("decrypted_test_file.txt", "wb") as f:
            f.write(decrypted_file_data)
        print("File 'encrypted_test_file.aes' đã được giải mã thành 'decrypted_test_file.txt'")

    except Exception as e:
        print(f"Lỗi khi xử lý file: {e}")