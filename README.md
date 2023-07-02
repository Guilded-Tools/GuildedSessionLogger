# Guilded Session Logger
A token logger; except for Guilded!

### POC
This repository is a proof of concept. The owner(s) and member(s) of this repository and organization take no responsibility for your actions.

### Important
This project logs session cookies. This means that your cookie may expire, unlike Discord tokens.

## What's Supported?
Windows only.
- **Guilded (desktop app)**
- **Reguilded (modified desktop app)**
- **Google Chrome**
- **Google Chrome Canary (Google Chrome SxS)**
- **Microsoft Edge**
- **Opera**
- **Opera GX**
- **Brave**
- **Firefox**
- Iridium (UNTESTED)
- Yandex (UNTESTED)
- Uran (UNTESTED)
- Amigo (UNTESTED)
- Torch (UNTESTED)
- Kometa (UNTESTED)
- Orbitum (UNTESTED)
- CentBrowser (UNTESTED)
- 7Star (UNTESTED)
- Sputnik (UNTESTED)
- Vivaldi (UNTESTED)
- Epic Privacy Browser (UNTESTED)

# Contributing
Issues and pull requests welcome!

If you tested this on a UNTESTED browser, make an issue!

# License
Read the [License](LICENSE)

# Logging in with a cookie
(Desktop only)
1. Open dev tools. (Ctrl + Shift + I on Windows, Command + Option + I on Mac)
2. Select "Console"
3. Paste the following into the console:
```javascript
function login(sessionCookie) {
  document.cookie = `hmac_signed_session=${sessionCookie}`;
  document.cookie = "authenticated=True";
  document.location.reload();
}

var loginCookie = 'your cookie in quotes or apostrophe here';
login(loginCookie);
```

# Making a request with a cookie
So you want to make a selfbot of a sort?

### Headers
These headers stay the same for most requests. You can always check the headers in the Network tab of Dev Tools if needed!
```json
{
    "accept": "application/json, text/javascript, */*; q=0.01",
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
```

## Python
```python
import requests
loginCookie = 'your login cookie here'

url = 'your request url here'
cookies = [
    ("hmac_signed_session", loginCookie),
    ("authenticated", "true"),
    ("gk", "electron_background_worker_watchdog%2Cuse_rtc_voice_connection%2Cmultiple_files_drag_drop%2Cshow_ptt_warning_banner%2Cnative_reaction_motion%2Cenable_progressive_image_uri_string%2Cenable_async_reactions%2Cnative_emotes_settings_screen%2Cserver_subs_prevent_native_subscribe_flow_ios%2Cenable_remove_reactions%2Cwebview_inject_cookies_disabled%2Cnative_audit_log_screen%2Candroid_soft_haptic_feedback%2Cenable_media_renderer_from_alternate_srcs%2Cwebrtc_vad%2Cmentionables_v2%2Cenable_scrollbar_v2%2Cwhimsical_bot_icons%2Cpause_stream_preview_unfocused%2Cnative_loopback_capture%2Crole_icon%2Creaction_picker_navbar_on_native%2Cmobile_virtualized_sidebar%2Cstyle_ios_text_input%2Cstyle_android_text_input%2Ccan_edit_socket_permissions%2Cyt_allow_custom_name%2Cchat_message_context_menu%2Cprofile_hover_card_v3%2Cpartner_program_v2%2Cvideo_streaming_pip_view_enabled%2Cshow_game_presence%2Cnative_update_app_overlay")
]
headers = {
    "accept": "application/json, text/javascript, */*; q=0.01",
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
payload = {} # your payload here. If no payload, put None
requests.request('method', headers=headers, payload=payload, cookies=dict(cookies), url=url)
```
