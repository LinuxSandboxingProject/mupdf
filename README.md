# mupdf
Sandboxed Mupdf Document Viewer

This modified version of Mupdf includes support for seccomp to implement sandbox support on linux systems using libseccomp

The original application can be found here: https://mupdf.com


Sandbox modes:
--------------

There are two different sandbox modes available at the moment:

- Invisible sandbox mode: this mode does not affect the normal functionality at all and will not be noticed by the user. It only blacklists some dangerous and rare syscalls and uses the no_new_privs flag to prevent the process to gain more privileges (e.g. by using suid)

- Read only mode: this mode does not allow writing files or access to the network. It is designed to only allow reading local files. By using a whitelist of allowed systemcalls, 90 % of the kernel interface is unavailable for the process, reducing the attack surface of the kernel significantly and limiting the movement of exploit code.



Future Work
-----------

It is possible to further restrict the list of allowed syscalls right before a document file is interpreted. This also includes blocking the use of syscalls needed for unix domain socket communication as used to communicate to IPC services like Dbus, which presents a weakpoint in sandboxing for modern Linux desktop systems.



Weak Points
-----------

One of the remaining weak points is the X11 Server. Without switching to wayland and blocking X11 access, keylogging is trivial.



Additional Sandbox support
--------------------------

Using linux namespaces container features, it is possible to further isolate the application from the rest of the system. With the bubblewrap project there is already some nice code that can be used for the purpose as demonstrated here: https://github.com/valoq/bwscripts/tree/master/profiles 
