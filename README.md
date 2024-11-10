# Cloud_server
Just a cloud server that uses SFTP made in python.

#SETUP
In order to make it a bit secure please follow these steps:

We setup the server and then we create a new user
sudo useradd -m -d /home/customhomedir myuser 
sudo passwd myuser

The directory must be owned by root and not writable by the user, i.e., /home/customhomedir must be owned by root with permissions set to 755 (readable and executable by all, but only writable by root).
If the directory is not owned by root or has improper permissions, the chroot might not activate correctly, allowing the user to access other parts of the filesystem.

You can check and set the correct permissions with the following commands:
sudo chown root:root /home/customhomedir
sudo chmod 755 /home/customhomedir

now we create the working directory for the user, i.e "main"
sudo mkdir main
sudo chown myuser:myuser /home/customhomedir/main
sudo chmod 700 /home/customehomedir/main

now we add the following lines at the end of sshd_config
sudo nano /etc/ssh/sshd_config

Match User myuser
   ForceCommand internal-sftp
   ChrootDirectory /home/customehomedir/main
   PermitTunnel no
   AllowAgentForwarding no
   AllowTcpForwarding no
   X11Forwarding no

  ctrl + x  - Enter
  y - Enter

sudo systemctl restart ssh
sudo reboot

Now the server is setup properly and secure.
We can modify the script now with our details (server ip, port, username, password, home folder location i.e /home/customhomedir/main)
and is ready to go 
Have fun


