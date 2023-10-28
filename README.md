# NinjaInjector
Classic Process Injection with Memory Evasion Techniques implemantation

What memory evasion techniques are used?

- Sleep Personal Implementation 
- Set PAGE_NOACCESS with VirtualProtectEx
- Encrypt/Decrypt Memory Regions with SystemFunction033
- Encrypt/Secrypt Shellcode to the entrypoint using XOR

# Page Guard

Forcing Page Guard Exceptions:

WriteProcessMemory:

![image](https://github.com/S12cybersecurity/NinjaInjector/assets/79543461/4879c1c4-13e4-4cde-898e-7310b9e7acd2)

CreateRemoteThread:

![image](https://github.com/S12cybersecurity/NinjaInjector/assets/79543461/288a02e8-21c6-4c38-9b3d-4d14aeea9b5a)

Handling Exceptions:

![image](https://github.com/S12cybersecurity/NinjaInjector/assets/79543461/89f949f0-d168-413e-92c0-2cc768bd8e51)

The flow code is the following:

![image](https://github.com/S12cybersecurity/NinjaInjector/assets/79543461/afa6ec95-bb27-46ad-8c5c-36ace4e98985)
