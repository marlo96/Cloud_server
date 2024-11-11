from tkinter import messagebox, filedialog, ttk, simpledialog
import os
import threading
import stat
import configparser
import base64
import paramiko
import tkinter as tk
from tkinter import messagebox
import sys

VERSION = "1.0"
#Made By Fallax with the help of CHAT-GPT
#####################


# Debug mode flag
debug_mode = False
DECRYPT = True


icon_path = 'res/favicon.ico'

dhostname = ""
dport = ""
dusername = ""
dpassword = ""

def show_popup(title, message):
    # Initialize Tkinter window
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    # Show a popup with the given title and message
    messagebox.showerror(title, message)
    root.quit()  # Close the Tkinter application

# The fixed encryption key
encryption_key = "zalsjo3fre5Zo2mNrG_ctiRwiQhGrOxIs_DnT8fUOkQ="

# XOR decryption function (reverse of the encryption)
def xor_decrypt(data, key):
    decrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
    return decrypted

# Function to Base64 decode
def base64_decode(data):
    return base64.urlsafe_b64decode(data).decode('utf-8')

# Decrypt the saved configuration from config.txt
def decrypt():
    global dhostname, dport, dusername, dpassword  # Declare as global
    config_path = "res/config.txt"

    # Check if the 'res' folder or 'config.txt' file exists
    if not os.path.exists(config_path):
        show_popup("Error", "'res/config.txt' not found. Run config.exe")
        sys.exit()

    # Read the encrypted values from the config file
    with open(config_path, "r") as config_file:
        lines = config_file.readlines()

    # Ensure the config file has the expected number of lines
    if len(lines) < 5:
        show_popup("Error", "'missing required configuration lines. Run config.exe")
        sys.exit()

    # Extract the encrypted values
    server_ip_encrypted = lines[1].split(" = ")[1].strip()
    server_port_encrypted = lines[2].split(" = ")[1].strip()
    server_username_encrypted = lines[3].split(" = ")[1].strip()
    server_password_encrypted = lines[4].split(" = ")[1].strip()

    # Base64 decode the encrypted data
    server_ip_encrypted = base64_decode(server_ip_encrypted)
    server_port_encrypted = base64_decode(server_port_encrypted)
    server_username_encrypted = base64_decode(server_username_encrypted)
    server_password_encrypted = base64_decode(server_password_encrypted)

    # XOR decrypt the data
    dhostname = xor_decrypt(server_ip_encrypted, encryption_key)
    dport = xor_decrypt(server_port_encrypted, encryption_key)
    dport = int(dport)
    dusername = xor_decrypt(server_username_encrypted, encryption_key)
    dpassword = xor_decrypt(server_password_encrypted, encryption_key)



if DECRYPT is not False and debug_mode is not False:
    print("Called decrypt function")
    DECRYPT = False
    decrypt()
if DECRYPT is not False:
    DECRYPT = False
    decrypt()




config = configparser.ConfigParser()
config.read('res/config.txt')  # Update the path if necessary
remote_path = config.get('Server', 'remote_path')
# Create the main window for the GUI
root = tk.Tk()
root.title("Halo.Cloud")
if os.path.exists(icon_path):
    root.iconbitmap(icon_path)


# Set the window size
root.geometry("800x500")

# Create a Frame to hold the Listbox and Scrollbar
frame = tk.Frame(root)
frame.pack(pady=20)

# Create a Listbox widget to display the contents of the directory
listbox = tk.Listbox(frame, width=80, height=20)
listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Create a Scrollbar widget and associate it with the Listbox
scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=listbox.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Configure the Listbox to work with the scrollbar
listbox.config(yscrollcommand=scrollbar.set)



# To keep track of the current path and history
current_path = remote_path
previous_paths = []

# SSH and SFTP connection objects
client = paramiko.SSHClient()
sftp = None


# Function to log detailed debug info
def debug_log(message):
    if debug_mode:
        print(message)


# Function to connect to the server and initialize SFTP connection
def connect_to_server():
    global client, sftp
    if not sftp:
        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(dhostname, dport, dusername, dpassword)
            sftp = client.open_sftp()
            debug_log("SFTP connection established.")
        except paramiko.AuthenticationException:
            debug_log("Authentication failed: Incorrect login details.")
            messagebox.showerror("Connection Error", "Authentication failed: Incorrect login details. Please check your username and password.")
            sys.exit()
        except paramiko.SSHException as e:
            debug_log(f"SSH error: {e}")
            response = messagebox.askyesno("Connection Error", f"SSH error: {e}. The server might be unresponsive. Try again?")
            if response:
                # Code for 'Yes' response
                connect_to_server()
            else:
                sys.exit()
        except Exception as e:
            # Check if the exception message contains errno 11001 (host not found)
            if '11001' in str(e):
                debug_log("DNS error: Hostname could not be resolved.")
                messagebox.showerror("Connection Error", f"Could not establish connection with {dhostname}. Please check your network and server address.")
            else:
                debug_log(f"Failed to connect to server: {e}")
                messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            sys.exit()





# Function to list files in the current directory


def list_files():
    global current_path
    connect_to_server()

    debug_log("Listing files via SFTP...")
    try:
        # Open an SFTP session
        sftp = client.open_sftp()

        # List files in the current directory
        files = sftp.listdir(current_path)

        # Close the SFTP session
        sftp.close()

        # Clear the listbox before inserting new data
        listbox.delete(0, tk.END)

        # Split files into two categories
        files_without_dot = []
        files_with_dot = []

        for file in files:
            if '.' in file:
                files_with_dot.append(file)
            else:
                files_without_dot.append(file)

        # Insert files without a dot first
        for file in files_without_dot:
            listbox.insert(tk.END, file)

        # Then insert files with a dot
        for file in files_with_dot:
            listbox.insert(tk.END, file)

        if not files:
            # If the directory is empty, display a blank message in the listbox
            listbox.insert(tk.END, "This directory is empty.")
            debug_log(f"{current_path} is empty.")

    except Exception as e:
        debug_log(f"Exception occurred: {str(e)}")
        messagebox.showerror("Connection Error", f"Failed to list files: {str(e)}")





# Function to handle double-click on an item
def on_item_double_click(event):
    global current_path, previous_paths
    # Get the index of the selected item
    selected_index = listbox.curselection()
    if selected_index:
        selected_item = listbox.get(selected_index)
        new_path = f"{current_path}/{selected_item}"

        debug_log(f"Double-clicked on: {selected_item}, Checking if it's a directory...")

        # Check if the selected item is a directory
        if selected_item and selected_item != '.' and selected_item != '..':
            # Use SFTP to check if it's a directory
            try:
                # Get file info using SFTP
                debug_log(f"Checking if {new_path} is a directory...")
                file_info = sftp.stat(new_path)

                # If file_info is a directory, it will have st_mode indicating a directory
                if stat.S_ISDIR(file_info.st_mode):
                    debug_log(f"{new_path} is a directory. Changing directory...")
                    # Add the current path to history before changing it
                    previous_paths.append(current_path)
                    current_path = new_path
                    list_files()
                else:
                    debug_log(f"{new_path} is not a directory.")
                    messagebox.showinfo("Not a Directory", f"{selected_item} is not a directory.")

            except Exception as e:
                debug_log(f"Exception occurred: {str(e)}")
                messagebox.showerror("Connection Error", f"Failed to check directory: {str(e)}")


# Function to go back to the previous directory
def go_back():
    global current_path, previous_paths
    if previous_paths:
        debug_log("Going back to previous directory...")
        # Pop the last path from the history stack
        current_path = previous_paths.pop()
        list_files()


# Add a frame to hold the buttons and make them appear together
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Add a "Refresh" button to relist files
refresh_button = tk.Button(button_frame, text="Refresh", command=list_files)
refresh_button.pack(side=tk.LEFT, padx=10)

# Add a "Back" button to go to the previous directory
back_button = tk.Button(button_frame, text="Back", command=go_back)
back_button.pack(side=tk.LEFT)


# Context menu for right-click
def on_right_click(event):
    context_menu.tk_popup(event.x_root, event.y_root)


def upload_files():
    # Ask for file selection dialog
    files = filedialog.askopenfilenames(title="Select files to upload")

    # Limit the number of selected files to 5
    if len(files) > 5:
        messagebox.showwarning("File Limit", "You can only upload a maximum of 5 files.")
        files = files[:5]  # Only take the first 5 files

    if not files:
        debug_log("No files selected for upload.")
        return

    # Show selected files in a confirmation dialog
    files_str = "\n".join([os.path.basename(file) for file in files])
    confirm = messagebox.askyesno("Confirm Upload", f"Do you want to upload these files?\n\n{files_str}")
    if not confirm:
        debug_log("File upload canceled.")
        return

    # Function to upload files with a progress bar
    def upload_thread():
        # Helper function to update the progress bar
        def progress_callback(transferred, total):
            progress = (transferred / total) * 100
            progress_bar['value'] = progress
            root.update_idletasks()  # Update the UI during the upload

        # Upload files to the server
        try:
            # Upload using the SFTP client (no need to reconnect every time)
            total_files = len(files)

            for i, file_path in enumerate(files):
                filename = os.path.basename(file_path)
                remote_file_path = f"{current_path}/{filename}"

                debug_log(f"Uploading {filename} to {remote_file_path}...")

                # Log the file and remote path
                debug_log(f"Source file path: {file_path}")
                debug_log(f"Remote file path: {remote_file_path}")

                # Upload the file with a progress callback
                sftp.put(file_path, remote_file_path,
                         callback=lambda transferred, total: progress_callback(transferred, total))

                debug_log(f"File {filename} uploaded.")

                # Reset the progress bar after upload
                progress_bar['value'] = 0
                root.update_idletasks()  # Update the UI to show the reset

                # Show confirmation message
                messagebox.showinfo("Upload Complete", f"File '{filename}' uploaded successfully!")

                # Update progress bar after each file upload
                progress_bar['value'] = ((i + 1) / total_files) * 100
                root.update_idletasks()  # Update the UI

            # Refresh file list after upload
            debug_log("Files uploaded successfully, refreshing file list...")
            list_files()

            # Show completion message
            messagebox.showinfo("Upload Complete", "All files uploaded successfully!")

        except Exception as e:
            debug_log(f"Upload failed: {str(e)}")
            messagebox.showerror("Upload Error", f"Failed to upload files: {str(e)}")
        finally:
            # Ensure progress bar is reset when the upload is complete
            progress_bar['value'] = 0
            root.update_idletasks()  # Update the UI

    # Start the upload in a new thread to avoid blocking the UI
    threading.Thread(target=upload_thread, daemon=True).start()


# Function to download files with progress bar
def download_file():
    # Get the selected file from the listbox
    selected_index = listbox.curselection()
    if not selected_index:
        messagebox.showwarning("No file selected", "Please select a file to download.")
        return

    selected_item = listbox.get(selected_index)
    remote_file_path = f"{current_path}/{selected_item}"

    # Ask user for the location to save the file
    local_file_path = filedialog.asksaveasfilename(defaultextension=".*", initialfile=selected_item,
                                                   title="Save File As")

    if not local_file_path:
        debug_log("Download canceled by the user.")
        return

    # Function to download the file with progress tracking
    def download_thread():
        def progress_callback(transferred, total):
            progress = (transferred / total) * 100
            progress_bar['value'] = progress
            root.update_idletasks()  # Update the UI during the download

        # Download file using the SFTP client
        try:
            debug_log(f"Downloading {selected_item} from {remote_file_path} to {local_file_path}...")

            # Download the file with progress tracking
            sftp.get(remote_file_path, local_file_path, callback=progress_callback)

            # Show confirmation message
            messagebox.showinfo("Download Complete", f"File '{selected_item}' downloaded successfully!")

        except Exception as e:
            debug_log(f"Download failed: {str(e)}")
            messagebox.showerror("Download Error", f"Failed to download the file: {str(e)}")
        finally:
            # Ensure progress bar is reset after download
            progress_bar['value'] = 0
            root.update_idletasks()

    # Start the download in a new thread
    threading.Thread(target=download_thread, daemon=True).start()


# Function to add a new folder
def add_folder():
    # Prompt the user for the folder name
    folder_name = simpledialog.askstring("New Folder", "Enter the folder name:")

    if not folder_name:
        return

    new_folder_path = f"{current_path}/{folder_name}"

    try:
        # Create the directory on the server using SFTP
        debug_log(f"Creating folder {new_folder_path} via SFTP...")

        # Using SFTP to create the directory
        sftp.mkdir(new_folder_path)  # SFTP method to create directory

        # Set permissions for the folder (this is an additional step, not native in mkdir)
        sftp.chmod(new_folder_path, 0o700)  # Set permissions to 0700

        messagebox.showinfo("Folder Created", f"Folder '{folder_name}' created successfully!")
        list_files()  # Refresh the file list

    except Exception as e:
        debug_log(f"Error occurred while creating folder: {str(e)}")
        messagebox.showerror("Error", f"Failed to create folder: {str(e)}")


def delete_folder():
    selected_index = listbox.curselection()
    if not selected_index:
        messagebox.showwarning("No folder selected", "Please select a folder to delete.")
        return

    selected_item = listbox.get(selected_index)
    remote_folder_path = f"{current_path}/{selected_item}"

    # Confirm folder deletion
    confirm = messagebox.askyesno("Confirm Delete",
                                  f"Are you sure you want to delete the folder '{selected_item}' and all of its contents?")
    if confirm:
        try:
            debug_log(f"Deleting folder {remote_folder_path} and all its contents...")

            # Use SFTP to delete the folder and its contents
            sftp = client.open_sftp()
            delete_recursive(sftp, remote_folder_path)
            sftp.close()

            messagebox.showinfo("Delete Complete",
                                f"Folder '{selected_item}' and its contents were deleted successfully!")
            list_files()  # Refresh the file list after deletion

        except Exception as e:
            debug_log(f"Error occurred while deleting folder: {str(e)}")
            messagebox.showerror("Delete Error", f"Failed to delete folder: {str(e)}")


def delete_recursive(sftp, remote_folder_path):
    """Helper function to recursively delete files and directories using SFTP"""
    for item in sftp.listdir_attr(remote_folder_path):
        item_path = remote_folder_path + '/' + item.filename
        if item.st_mode & 0o40000:  # Directory
            delete_recursive(sftp, item_path)  # Recursively delete directory contents
            sftp.rmdir(item_path)  # Remove the empty directory
        else:
            sftp.remove(item_path)  # Remove file

    # Finally, remove the main folder
    sftp.rmdir(remote_folder_path)




# Function to delete a file
def delete_file():
    selected_index = listbox.curselection()
    if not selected_index:
        messagebox.showwarning("No file selected", "Please select a file to delete.")
        return

    selected_item = listbox.get(selected_index)
    remote_file_path = f"{current_path}/{selected_item}"

    # Confirm deletion
    confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {selected_item}?")
    if confirm:
        try:
            debug_log(f"Deleting {selected_item} from {remote_file_path}...")
            sftp.remove(remote_file_path)
            messagebox.showinfo("Delete Complete", f"File '{selected_item}' deleted successfully!")
            list_files()  # Refresh the file list after deletion
        except Exception as e:
            messagebox.showerror("Delete Error", f"Failed to delete the file: {str(e)}")


# Function to close the right-click menu
def cancel():
    context_menu.unpost()


# Create the right-click context menu
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Create Folder", command=add_folder)
context_menu.add_separator()
context_menu.add_command(label="Upload Files", command=upload_files)
context_menu.add_separator()
context_menu.add_command(label="Download File", command=download_file)
context_menu.add_separator()
context_menu.add_command(label="Delete File", command=delete_file)
context_menu.add_command(label="Delete Folder", command=delete_folder)

# Add a separator line above the "Cancel" option
context_menu.add_separator()
context_menu.add_command(label="Cancel", command=cancel)



# Bind events to handle right-click and double-click
listbox.bind("<Double-1>", on_item_double_click)
listbox.bind("<Button-3>", on_right_click)


# Add a progress bar for file uploads/downloads
progress_bar = ttk.Progressbar(root, length=400, mode='determinate', maximum=100)
progress_bar.pack(pady=10)


# Run the GUI
list_files()  # Initial file listing
root.mainloop()

