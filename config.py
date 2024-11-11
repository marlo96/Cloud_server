import base64
import tkinter as tk
from tkinter import messagebox
import os

VERSION = "1.0"

# The fixed encryption key
encryption_key = "zalsjo3fre5Zo2mNrG_ctiRwiQhGrOxIs_DnT8fUOkQ="


# XOR encryption function
def xor_encrypt(data, key):
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
    return encrypted


# Function to Base64 encode
def base64_encode(data):
    return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8')


# Encrypt and save the data in res/config.txt
def encrypt(server_ip, server_port, server_username, server_password):
    # Encrypt each value using XOR encryption
    server_ip_encrypted = xor_encrypt(server_ip, encryption_key)
    server_port_encrypted = xor_encrypt(str(server_port), encryption_key)  # Ensure it's a string
    server_username_encrypted = xor_encrypt(server_username, encryption_key)
    server_password_encrypted = xor_encrypt(server_password, encryption_key)

    # Base64 encode the XOR encrypted values
    server_ip_encrypted = base64_encode(server_ip_encrypted)
    server_port_encrypted = base64_encode(server_port_encrypted)
    server_username_encrypted = base64_encode(server_username_encrypted)
    server_password_encrypted = base64_encode(server_password_encrypted)

    # Check if the directory 'res' exists, create it if not
    if not os.path.exists("res"):
        os.makedirs("res")

    # Check if the file exists, create it if not
    if not os.path.exists("res/config.txt"):
        with open("res/config.txt", "w") as config_file:
            config_file.write(f"[Server]\n")
            config_file.write(f"hostname = {server_ip_encrypted}\n")
            config_file.write(f"port = {server_port_encrypted}\n")
            config_file.write(f"username = {server_username_encrypted}\n")
            config_file.write(f"password = {server_password_encrypted}\n")
            config_file.write(f"remote_path = /main\n")
    else:
        # If the file exists, just append the encrypted configuration data
        with open("res/config.txt", "w") as config_file:
            config_file.write(f"[Server]\n")
            config_file.write(f"hostname = {server_ip_encrypted}\n")
            config_file.write(f"port = {server_port_encrypted}\n")
            config_file.write(f"username = {server_username_encrypted}\n")
            config_file.write(f"password = {server_password_encrypted}\n")
            config_file.write(f"remote_path = /main\n")

    messagebox.showinfo("Success", "Configuration has been encrypted and saved to res/config.txt.")


# Create the GUI window
def create_gui():
    def on_submit():
        # Collect values from the entry fields
        server_ip = entry_ip.get()
        server_port = entry_port.get()
        server_username = entry_username.get()
        server_password = entry_password.get()

        # Ensure all fields are filled
        if not server_ip or not server_port or not server_username or not server_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        # Encrypt and save the configuration
        encrypt(server_ip, server_port, server_username, server_password)

        # Clear all fields after saving
        entry_ip.delete(0, tk.END)
        entry_port.delete(0, tk.END)
        entry_username.delete(0, tk.END)
        entry_password.delete(0, tk.END)

    def validate_port_input(char):
        return char.isdigit()

    # Create the main window
    window = tk.Tk()
    window.title("Halo.Cloud")

    # Set the window icon, check if it exists first
    icon_path = 'res/favicon.ico'
    if os.path.exists(icon_path):
        window.iconbitmap(icon_path)
    else:
        print(f"Icon not found at {icon_path}, running without icon.")

    # Create labels and entries
    label_ip = tk.Label(window, text="Server IP:")
    label_ip.grid(row=0, column=0, padx=10, pady=5)
    entry_ip = tk.Entry(window, width=30)
    entry_ip.grid(row=0, column=1, padx=10, pady=5)

    label_port = tk.Label(window, text="Server Port:")
    label_port.grid(row=1, column=0, padx=10, pady=5)

    # Validate port input to accept only numbers
    validate_port_cmd = (window.register(validate_port_input), '%S')
    entry_port = tk.Entry(window, width=30, validate="key", validatecommand=validate_port_cmd)
    entry_port.grid(row=1, column=1, padx=10, pady=5)

    label_username = tk.Label(window, text="Username:")
    label_username.grid(row=2, column=0, padx=10, pady=5)
    entry_username = tk.Entry(window, width=30)
    entry_username.grid(row=2, column=1, padx=10, pady=5)

    label_password = tk.Label(window, text="Password:")
    label_password.grid(row=3, column=0, padx=10, pady=5)
    entry_password = tk.Entry(window, width=30, show="*")
    entry_password.grid(row=3, column=1, padx=10, pady=5)

    # Create submit button
    submit_button = tk.Button(window, text="Save", command=on_submit)
    submit_button.grid(row=4, columnspan=2, pady=10)

    # Run the GUI
    window.mainloop()


# Example usage
if __name__ == "__main__":
    create_gui()
