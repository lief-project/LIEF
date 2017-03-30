NppFTP Readme:

To start using the plugin, use the "Show NppFTp Window" option from the plugins menu, or use the Notepad++ toolbar button.
To find some information about the plugin, use the "About NppFTP" option from the menu. There is a button there for a link to the NppFTP site.


Configuring:
------------
There are two configuration dialogs for NppFTP. These can be accessed by clicking on the settings button in the NppFTP toolbar (cog icon).

-General configuration
In the general configuration dialog, the default cache location can be entered. See 'Cache paths' for more details. It will map to the root directory on the server ('/')
and if no other cache locations are provided by a profile, this will always be the target.

-Profile configuration:
In the profiles configuration dialog, profiles can be created, modified and deleted. Initially, no profiles exists and no connection can be made.
To create a new profile, click the Add profile button and enter the name of the new profile. Please provide an unique name for your own ease of use.
Renaming and delting a profile is done with the corresponding buttons.
In the connections tab, settings for each connection be be entered. At minimum provide a hostname (address) and port.
In the transfers tab, settings for FTP transfers can be edited.
In the cache tab, specific cache mappings can be added for the selected profile. See 'Cache paths' for more details.

Cache paths:
------------
When downloading files form a server, they are by default stored in the cache. When a file in the cache is saved, it will automatically be uploaded. To allow more fine grained control over what files go to where, a cache mapping can be created. A cache map consists of a local directory and an external path. The local directory provides the location on the local computer to look for files to upload and to download to. For example, if "C:\ftpfiles\myserver\home" were entered, files in that directory and subdirectory would be transferred to the correspodning path on the external server. The external path provides the location to download files from and upload to. For example, "/home/myuser/public_html/" would map files on that path and its subpaths to the corresponding directory.
Determining a cache map for a filetransfer is done on a first match basis (rather than 'best fit'). For example, consider the following scenario:
Profile cache maps:
Local                        External
C:\webfiles                  /home/user/public_html
C:\webfiles                  /home/user2/public_html
C:\rootfiles                 /root
D:\serverfilesystem          /

General cache map:
C:\myuser@server.com\        / (fixed)

Downloads:
The external file "/home/user/public_html/index.html" would be transferred to "C:\webfiles\index.html"
The external file "/home/user/.bash_rc" would be transferred to "D:\serverfilesystem\home\user\.bash_rc"
The external file "/root/apache.conf" would be transferred to "C:\rootfiles\apache.conf"
The external file "/vmlinuz.img" would be transferred to "D:\serverfilesystem\vmlinuz.img"
No download would be directed to "C:\myuser@server.com\"

Uploads:
The local file "C:\webfiles\home\user\.bash_rc" would be transferred to "/home/user/public_html/home/user/.bash_rc" (user2 will NOT be considered)
The local file "D:\serverfilesystem\boot\grub\menu.lst" would be transferred to "/boot/grub/menu.lst"
The local file "C:\myuser@server.com\home\user\public_html\index.html" would be transferred to "/home/user/public_html/index.html"

Ordering is important. The general cache map will always be considered last, the profile maps will be considered from top to bottom. So if
D:\serverfilesystem          /
were to be at the top, ALL files would be downloaded to "D:\serverfilesystem"

Toolbar:
--------
The toolbar provides the following buttons:
Connected/Disconnect: Either connect to a server from a profile form a dropdown menu, or disconnect from the current server.
Download file: If a file is selected in the treeview, download it to the cache.
Upload file: If a directory is selected in the treeview, upload the current file to that directory.
Refresh: If a directory is selected in the treeview, refresh its contents.
Abort: If a transfer is active, abort it.
Quote: send a direct command to the server (Currently not implemented)
Settings: Access settings dialogs.
Show messages: Hide or Show the messages window.

Treeview:
---------
If an ftp session is active, the treview will show the files on the server. Some actions of the toolbar depend on the selected object in the treeview (see toolbar).
Doubleclicking on a directory will show its contents. Doubleclicking on a file will download it to the cache and open it.

Queue:
------
The queue window shows the currently active and queued filetransfers, along with their progress and filepath. Rightclicking on an item
allows to abort or cancel it, depending whether the transfer is active or queued.

Message window:
---------------
The messagewindow shows some output of various operations. If something goes wrong, look for errors here.
Notifications are blue, server messages are green, errors are red.