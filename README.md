## 📌 PinHoarder

![PinHoarder Logo](imgs/Screenshot_20250817-143141_1.png)

**PinHoarder** is a **Pinterest Mass Image Downloader** that lets you collect and save images from Pinterest using simple command-line options.

---

## ✨ Features

- 🔍 Search by multiple keywords (`--kw "cat,dog"` or from file with `--kf keywords.txt`)
- 📂 Save results as `.txt` link lists or download all images with `--download`
- 📊 Control number of images with `--max` (default 20)
- 📜 Load more results with `--scroll` (simulates scrolling down)
- 📁 Custom output directory with `-o` (default: `./dumpimgs`)
- ⚡ Lightweight (only depends on `requests`)

---

## 💿 Installation

```bash
git clone https://github.com/BilalHaiderID/PinHoarder.git
cd PinHoarder
pip install -r requirements.txt
```

---

## 📝 Usage

```bash
# Save only links (default, 20 per keyword)
python3 pinhoarder.py --kw "programmer,putin"

# Save 50 images per keyword, download them
python3 pinhoarder.py --kw "elon musk" --max 50 --download

# Load keywords from file, scroll 3 times, output to custom dir
python3 pinhoarder.py --kf keywords.txt --scroll 3 -o results --download
```

---

## 🗞️ Arguments

| Flag | Alias | Description |
|------|--------|-------------|
| `--kw` | `--keywords` | Comma-separated keywords |
| `--kf` | `--keywordsfile` | File with one keyword per line |
| `--max` | `--maxdump` | Maximum number of images per keyword (default 20) |
| `--scroll` |  -  | Number of times to scroll (default 1) |
| `-o` | `--output` | Output directory (default `./dumpings`) |
| `-d` | `--download` | Download images (otherwise saves links only) |

---


## Author

Created with ❤️ by **@bilalhaiderid**
