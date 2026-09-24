# PS5 SlopKit

A PS5 jailbreak host based on the WebKit exploit, supporting firmware 9.00–12.00.
On success it boots the ELF Loader (port 9021), automatically sends the PS5
Payload Manager, then closes the browser. All resources are cached to the
console on the first visit and work fully offline afterwards.

## Usage

**Online**

Open the page in the PS5 browser and press Jailbreak. The first visit downloads
the cache; afterwards it works completely offline.

**Local deployment (recommended for users in China)**

Run inside the repository directory:  python server.py

Open the `http://<PC-IP>:8000/` address printed in the terminal with the PS5
browser.

**Already jailbroken**

If the console has already been jailbroken in the current boot cycle, press
PAYLOADS to go straight to the payload menu.

## Notes & Troubleshooting

- Do **not** close or switch away from the page during the jailbreak.
- Success rates vary per attempt with race-based exploits. **Failed** means you
  can press the circle again to retry in place; **Reboot need** means the kernel
  state is dirty and the console **must be rebooted**.
- Do not run the jailbreak twice in the same boot; the page has re-entry
  protection built in.
- Updates: fully automatic in local mode. For static hosting (GitHub Pages) I
  update the cache manifest version number; if an update does not take effect,
  clear the PS browser cache once.
- Direct connections to GitHub Pages from China are unreliable; local deployment
  is recommended.
## Supported Firmware
9.00 / 9.05 / 9.20 / 9.40 / 9.60 / 10.00 / 10.01 / 10.20 / 10.40 / 10.60 /
11.00 / 11.20 / 11.40 / 11.60 / 12.00

## Credits

- [@jordyidk](https://github.com/jordyidk/slopkit) & contributors — slopkit
- [@itsPLK](https://github.com/itsPLK) — [ps5-webkit-autoloader](https://github.com/itsPLK/ps5-webkit-autoloader) (parts of this project's implementation were adapted from it)
- This project was developed with AI assistance (GLM5.3 & MiMo2.6)
- Thanks to everyone who contributes to the PS5 homebrew scene
