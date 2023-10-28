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

![image](https://github.com/S12cybersecurity/NinjaInjector/assets/79543461/de4b0a62-f5ff-4b98-923c-31817377337c)

CreateRemoteThread:

![image](https://github.com/S12cybersecurity/NinjaInjector/assets/79543461/98decf3f-d644-4f57-b836-1effd8b23112)


Handling Exceptions:

![image](https://github.com/S12cybersecurity/NinjaInjector/assets/79543461/f67c52dc-130a-4f48-a8da-6c0039315e14)


The flow code is the following:

![image](https://github.com/S12cybersecurity/NinjaInjector/assets/79543461/d6a19688-02ca-46cf-ac6e-dd1c93c58775)
